// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <assert.h>
#include <sks_ta.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "handle.h"
#include "pkcs11_token.h"
#include "serializer.h"
#include "sks_helpers.h"

/* Provide 3 slots/tokens, ID is token index */
#define TOKEN_COUNT	3

/* Static allocation of tokens runtime instances (reset to 0 at load) */
struct ck_token ck_token[TOKEN_COUNT];

static struct client_list pkcs11_client_list;

static void close_ck_session(struct pkcs11_session *session);

/* Static allocation of tokens runtime instances */
struct ck_token *get_token(unsigned int token_id)
{
	if (token_id > TOKEN_COUNT)
		return NULL;

	return &ck_token[token_id];
}

unsigned int get_token_id(struct ck_token *token)
{
	assert(token >= ck_token && token < &ck_token[TOKEN_COUNT]);

	return token - ck_token;
}

/* Client */
struct pkcs11_client *tee_session2client(uintptr_t tee_session)
{
	struct pkcs11_client *client;

	TAILQ_FOREACH(client, &pkcs11_client_list, link) {
		if (client == (void *)tee_session)
			return client;
	}

	return NULL;
}

uintptr_t register_client(void)
{
	struct pkcs11_client *client;

	client = TEE_Malloc(sizeof(*client), TEE_MALLOC_FILL_ZERO);
	if (!client)
		return 0;

	TAILQ_INSERT_HEAD(&pkcs11_client_list, client, link);
	TAILQ_INIT(&client->session_list);
	handle_db_init(&client->session_handle_db);

	return (uintptr_t)(void *)client;
}

void unregister_client(uintptr_t tee_session)
{
	struct pkcs11_client *client = tee_session2client(tee_session);
	struct pkcs11_session *session;
	struct pkcs11_session *next;

	if (!client) {
		EMSG("Unexpected invalid TEE session handle");
		return;
	}

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next) {
		close_ck_session(session);
	}

	TAILQ_REMOVE(&pkcs11_client_list, client, link);
	handle_db_destroy(&client->session_handle_db);
	TEE_Free(client);
}

static int pkcs11_token_init(unsigned int id)
{
	struct ck_token *token = init_token_db(id);

	if (!token)
		return 1;

	if (token->state != PKCS11_TOKEN_RESET) {
		/* Token is already in a valid state */
		return 0;
	}

	/* Initialize the token runtime state */
	token->state = PKCS11_TOKEN_READ_WRITE;

	return 0;
}

int pkcs11_init(void)
{
	unsigned int id;

	for (id = 0; id < TOKEN_COUNT; id++)
		if (pkcs11_token_init(id))
			return 1;

	TAILQ_INIT(&pkcs11_client_list);

	return 0;
}

void pkcs11_deinit(void)
{
	unsigned int id;

	for (id = 0; id < TOKEN_COUNT; id++)
		close_persistent_db(get_token(id));
}

bool pkcs11_session_is_read_write(struct pkcs11_session *session)
{
	switch (session->state) {
	case PKCS11_SESSION_PUBLIC_READ_WRITE:
	case PKCS11_SESSION_USER_READ_WRITE:
	case PKCS11_SESSION_SO_READ_WRITE:
		return true;
	default:
		return false;
	}
}

struct pkcs11_session *sks_handle2session(uint32_t handle,
					  uintptr_t tee_session)
{
	struct pkcs11_client *client = tee_session2client(tee_session);

	return handle_lookup(&client->session_handle_db, (int)handle);
}

/*
 * PKCS#11 expects an session must finalize (or cancel) an operation
 * before starting a new one.
 *
 * enum pkcs11_proc_state provides the valid operation states for a
 * PKCS#11 session.
 *
 * set_processing_state() changes the session operation state.
 *
 * check_processing_state() checks the session is in the expected
 * operation state.
 */
int set_processing_state(struct pkcs11_session *pkcs_session,
			 enum pkcs11_proc_state state)
{
	if (!pkcs_session)
		return 1;

	/*
	 * Caller can move to any state from the ready state.
	 * Caller can always return to the ready state.
	 */
	if (pkcs_session->processing == PKCS11_SESSION_READY ||
	    state == PKCS11_SESSION_READY) {
		pkcs_session->processing = state;
		return 0;
	}

	/* Allowed transitions on dual disgest/cipher or authen/cipher */
	switch (state) {
	case PKCS11_SESSION_DIGESTING_ENCRYPTING:
		if (pkcs_session->processing == PKCS11_SESSION_ENCRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_DIGESTING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	case PKCS11_SESSION_DECRYPTING_DIGESTING:
		if (pkcs_session->processing == PKCS11_SESSION_DECRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_DIGESTING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	case PKCS11_SESSION_SIGNING_ENCRYPTING:
		if (pkcs_session->processing == PKCS11_SESSION_ENCRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_SIGNING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	case PKCS11_SESSION_DECRYPTING_VERIFYING:
		if (pkcs_session->processing == PKCS11_SESSION_DECRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_VERIFYING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	default:
		break;
	}

	/* Transition not allowed */
	return 1;
}

int check_processing_state(struct pkcs11_session *pkcs_session,
			   enum pkcs11_proc_state state)
{
	if (!pkcs_session)
		return 1;

	return (pkcs_session->processing == state) ? 0 : 1;
}

static void cipher_pin(TEE_ObjectHandle key_handle, uint8_t *buf, size_t len)
{
	uint8_t iv[16] = { 0 };
	uint32_t size = len;
	TEE_OperationHandle tee_op_handle = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_AllocateOperation(&tee_op_handle,
				    TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_ENCRYPT, 128);
	if (res)
		TEE_Panic(0);

	res = TEE_SetOperationKey(tee_op_handle, key_handle);
	if (res)
		TEE_Panic(0);

	TEE_CipherInit(tee_op_handle, iv, sizeof(iv));

	res = TEE_CipherDoFinal(tee_op_handle, buf, len, buf, &size);
	if (res || size != SKS_TOKEN_PIN_SIZE)
		TEE_Panic(0);

	TEE_FreeOperation(tee_op_handle);
}

/* ctrl=[slot-id][pin-size][pin][label], in=unused, out=unused */
uint32_t entry_ck_token_initialize(TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	uint32_t pin_size;
	void *pin;
	char label[32 + 1];
	struct ck_token *token;
	uint8_t *cpin = NULL;
	int pin_rc;
	struct pkcs11_client *client;

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &label, SKS_TOKEN_LABEL_SIZE);
	if (rv)
		return rv;

	if (pin_size > SKS_TOKEN_PIN_SIZE)
		return SKS_FAILED;

	token = get_token(token_id);
	if (!token)
		return SKS_CKR_SLOT_ID_INVALID;

	if (token->db_main->flags & SKS_CKFT_SO_PIN_LOCKED) {
		IMSG("Token SO PIN is locked");
		return SKS_CKR_PIN_LOCKED;
	}

	TAILQ_FOREACH(client, &pkcs11_client_list, link) {
		if (!TAILQ_EMPTY(&client->session_list)) {
			return SKS_CKR_SESSION_EXISTS;
		}
	}

	cpin = TEE_Malloc(SKS_TOKEN_PIN_SIZE, TEE_MALLOC_FILL_ZERO);
	TEE_MemMove(cpin, pin, pin_size);
	cipher_pin(token->pin_hdl[0], cpin, SKS_TOKEN_PIN_SIZE);

	if (!token->db_main->so_pin_size) {
		TEE_MemMove(token->db_main->so_pin, cpin, SKS_TOKEN_PIN_SIZE);
		token->db_main->so_pin_size = pin_size;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin),
				     sizeof(token->db_main->so_pin));
		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin_size),
				     sizeof(token->db_main->so_pin_size));

		goto inited;
	}

	pin_rc = 0;
	if (token->db_main->so_pin_size != pin_size)
		pin_rc = 1;
	if (buf_compare_ct(token->db_main->so_pin, cpin,
			   SKS_TOKEN_PIN_SIZE))
		pin_rc = 1;

	if (pin_rc) {
		token->db_main->flags |= SKS_CKFT_SO_PIN_COUNT_LOW;
		token->db_main->so_pin_count++;

		if (token->db_main->so_pin_count == 6)
			token->db_main->flags |= SKS_CKFT_SO_PIN_FINAL_TRY;
		if (token->db_main->so_pin_count == 7)
			token->db_main->flags |= SKS_CKFT_SO_PIN_LOCKED;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      flags),
				     sizeof(token->db_main->flags));
		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin_count),
				     sizeof(token->db_main->so_pin_count));

		TEE_Free(cpin);
		return SKS_CKR_PIN_INCORRECT;
	}

	token->db_main->flags &= ~(SKS_CKFT_SO_PIN_COUNT_LOW |
				   SKS_CKFT_SO_PIN_FINAL_TRY);
	token->db_main->so_pin_count = 0;

inited:
	TEE_MemMove(token->db_main->label, label, SKS_TOKEN_LABEL_SIZE);
	token->db_main->flags |= SKS_CKFT_TOKEN_INITIALIZED;

	update_persistent_db(token,
			     offsetof(struct token_persistent_main, label),
			     sizeof(token->db_main->label));

	update_persistent_db(token,
			     offsetof(struct token_persistent_main,
				      so_pin_count),
			     sizeof(token->db_main->so_pin_count));

	update_persistent_db(token,
			     offsetof(struct token_persistent_main, flags),
			     sizeof(token->db_main->flags));

	label[32] = '\0';
	IMSG("Token \"%s\" is happy to be initilialized", label);

	TEE_Free(cpin);

	return SKS_OK;
}

uint32_t entry_ck_slot_list(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const size_t out_size = sizeof(uint32_t) * TOKEN_COUNT;
	uint32_t *id;
	unsigned int n;

	if (ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < out_size) {
		out->memref.size = out_size;
		return SKS_SHORT_BUFFER;
	}

	for (id = out->memref.buffer, n = 0; n < TOKEN_COUNT; n++, id++)
		*id = (uint32_t)n;

	out->memref.size = out_size;

	return SKS_OK;
}

uint32_t entry_ck_slot_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	struct ck_token *token;
	const char desc[] = SKS_CRYPTOKI_SLOT_DESCRIPTION;
	const char manuf[] = SKS_CRYPTOKI_SLOT_MANUFACTURER;
	const char hwver[2] = SKS_CRYPTOKI_SLOT_HW_VERSION;
	const char fwver[2] = SKS_CRYPTOKI_SLOT_FW_VERSION;
	struct sks_slot_info info;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(struct sks_slot_info)) {
		out->memref.size = sizeof(struct sks_slot_info);
		return SKS_SHORT_BUFFER;
	}

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_CKR_SLOT_ID_INVALID;

	TEE_MemFill(&info, 0, sizeof(info));

	PADDED_STRING_COPY(info.slotDescription, desc);
	PADDED_STRING_COPY(info.manufacturerID, manuf);

	info.flags |= SKS_CKFS_TOKEN_PRESENT;
	info.flags |= SKS_CKFS_REMOVABLE_DEVICE;
	info.flags &= ~SKS_CKFS_HW_SLOT;

	TEE_MemMove(&info.hardwareVersion, &hwver, sizeof(hwver));
	TEE_MemMove(&info.firmwareVersion, &fwver, sizeof(fwver));

	out->memref.size = sizeof(struct sks_slot_info);
	TEE_MemMove(out->memref.buffer, &info, out->memref.size);

	return SKS_OK;
}

uint32_t entry_ck_token_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	struct ck_token *token;
	const char manuf[] = SKS_CRYPTOKI_TOKEN_MANUFACTURER;
	const char sernu[] = SKS_CRYPTOKI_TOKEN_SERIAL_NUMBER;
	const char model[] = SKS_CRYPTOKI_TOKEN_MODEL;
	const char hwver[] = SKS_CRYPTOKI_TOKEN_HW_VERSION;
	const char fwver[] = SKS_CRYPTOKI_TOKEN_FW_VERSION;
	struct sks_token_info info;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(struct sks_token_info)) {
		out->memref.size = sizeof(struct sks_token_info);
		return SKS_SHORT_BUFFER;
	}

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_CKR_SLOT_ID_INVALID;

	TEE_MemFill(&info, 0, sizeof(info));

	PADDED_STRING_COPY(info.label, token->db_main->label);
	PADDED_STRING_COPY(info.manufacturerID, manuf);
	PADDED_STRING_COPY(info.model, model);
	PADDED_STRING_COPY(info.serialNumber, sernu);

	info.flags = token->db_main->flags;

	/* TODO */
	info.ulMaxSessionCount = ~0;
	info.ulSessionCount = ~0;
	info.ulMaxRwSessionCount = ~0;
	info.ulRwSessionCount = ~0;
	/* TODO */
	info.ulMaxPinLen = 128;
	info.ulMinPinLen = 10;
	/* TODO */
	info.ulTotalPublicMemory = ~0;
	info.ulFreePublicMemory = ~0;
	info.ulTotalPrivateMemory = ~0;
	info.ulFreePrivateMemory = ~0;

	TEE_MemMove(&info.hardwareVersion, &hwver, sizeof(hwver));
	TEE_MemMove(&info.firmwareVersion, &fwver, sizeof(hwver));

	// TODO: get time and convert from refence into YYYYMMDDhhmmss/UTC
	TEE_MemFill(info.utcTime, 0, sizeof(info.utcTime));

	/* Return to caller with data */
	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return SKS_OK;
}

uint32_t entry_ck_token_mecha_ids(TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	struct ck_token *token;
	const uint32_t mecha_list[] = {
		SKS_CKM_AES_ECB,
		SKS_CKM_AES_CBC,
		SKS_CKM_AES_CBC_PAD,
		SKS_CKM_AES_CTS,
		SKS_CKM_AES_CTR,
		SKS_CKM_AES_GCM,
		SKS_CKM_AES_CCM,
	};

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(mecha_list)) {
		out->memref.size = sizeof(mecha_list);
		return SKS_SHORT_BUFFER;
	}

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_CKR_SLOT_ID_INVALID;

	/* TODO: can a token support a restricted mechanism list */
	out->memref.size = sizeof(mecha_list);
	TEE_MemMove(out->memref.buffer, mecha_list, sizeof(mecha_list));

	return SKS_OK;
}

uint32_t entry_ck_token_mecha_info(TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	uint32_t type;
	struct ck_token *token;
	struct sks_mechanism_info info;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(info)) {
		out->memref.size = sizeof(info);
		return SKS_SHORT_BUFFER;
	}

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &type, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_CKR_SLOT_ID_INVALID;

	TEE_MemFill(&info, 0, sizeof(info));

	/* TODO: full list of supported algorithm/mechanism */
	switch (type) {
	case SKS_CKM_AES_GCM:
	case SKS_CKM_AES_CCM:
		info.flags |= SKS_CKFM_SIGN | SKS_CKFM_VERIFY;
	case SKS_CKM_AES_ECB:
	case SKS_CKM_AES_CBC:
	case SKS_CKM_AES_CBC_PAD:
	case SKS_CKM_AES_CTS:
	case SKS_CKM_AES_CTR:
		info.flags |= SKS_CKFM_ENCRYPT | SKS_CKFM_DECRYPT |
			     SKS_CKFM_WRAP | SKS_CKFM_UNWRAP | SKS_CKFM_DERIVE;
		info.min_key_size = 128;
		info.max_key_size = 256;
		break;

	default:
		break;
	}

	out->memref.size = sizeof(info);
	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return SKS_OK;
}

static void set_session_state(struct pkcs11_client *client,
			      struct pkcs11_session *session, bool readonly)
{
	struct pkcs11_session *sess;
	enum pkcs11_session_state state = PKCS11_SESSION_RESET;

	/*
	 * No need to check all client session, only the first session on
	 * target token gives client loggin configuration.
	 */
	TAILQ_FOREACH(sess, &client->session_list, link) {
		if (sess == session)
			MSG("session found in list!!!");
		if (sess->token != session->token)
			continue;

		switch (sess->state) {
		case PKCS11_SESSION_PUBLIC_READ_WRITE:
		case PKCS11_SESSION_PUBLIC_READ_ONLY:
			state = PKCS11_SESSION_PUBLIC_READ_WRITE;
			break;
		case PKCS11_SESSION_USER_READ_WRITE:
		case PKCS11_SESSION_USER_READ_ONLY:
			state = PKCS11_SESSION_USER_READ_WRITE;
			break;
		case PKCS11_SESSION_SO_READ_WRITE:
			state = PKCS11_SESSION_SO_READ_WRITE;
			break;
		default:
			TEE_Panic(0);
		}
		break;
	 }

	switch (state) {
	case PKCS11_SESSION_USER_READ_WRITE:
		session->state = readonly ? PKCS11_SESSION_PUBLIC_READ_ONLY :
					  PKCS11_SESSION_PUBLIC_READ_WRITE;
		break;
	case PKCS11_SESSION_SO_READ_WRITE:
		/* SO cannot open read-only sessions */
		if (readonly)
			TEE_Panic(0);

		session->state = PKCS11_SESSION_PUBLIC_READ_ONLY;
		break;
	default:
		session->state = readonly ? PKCS11_SESSION_PUBLIC_READ_ONLY :
					  PKCS11_SESSION_PUBLIC_READ_WRITE;
		break;
	}
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
static uint32_t open_ck_session(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, bool readonly)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	struct ck_token *token;
	struct pkcs11_session *session;
	struct pkcs11_client *client;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_CKR_SLOT_ID_INVALID;

	if (!readonly && token->state == PKCS11_TOKEN_READ_ONLY) {
		return SKS_CKR_TOKEN_WRITE_PROTECTED;
	}

	client = tee_session2client(tee_session);
	if (!client) {
		EMSG("Unexpected invlaid TEE session handle");
		return SKS_FAILED;
	}

	if (readonly) {
		TAILQ_FOREACH(session, &client->session_list, link) {
			if (session->state == PKCS11_SESSION_SO_READ_WRITE) {
				return SKS_CKR_SESSION_READ_WRITE_SO_EXISTS;
			}
		}
	}


	session = TEE_Malloc(sizeof(*session), 0);
	if (!session)
		return SKS_MEMORY;

	session->handle = handle_get(&client->session_handle_db, session);
	session->tee_session = tee_session;
	session->processing = PKCS11_SESSION_READY;
	session->tee_op_handle = TEE_HANDLE_NULL;
	session->token = token;
	session->proc_id = SKS_UNDEFINED_ID;

	session->client = client;

	LIST_INIT(&session->object_list);

	set_session_state(client, session, readonly);

	TAILQ_INSERT_HEAD(&client->session_list, session, link);

	*(uint32_t *)out->memref.buffer = session->handle;
	out->memref.size = sizeof(uint32_t);

	return SKS_OK;
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
uint32_t entry_ck_token_ro_session(uintptr_t teesess, TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out)
{
	return ck_token_session(teesess, ctrl, in, out, true);
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
uint32_t entry_ck_token_rw_session(uintptr_t teesess, TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out)
{
	return ck_token_session(teesess, ctrl, in, out, false);
}

static void close_ck_session(struct pkcs11_session *session)
{
	if (session->tee_op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(session->tee_op_handle);

	while (!LIST_EMPTY(&session->object_list))
		destroy_object(session, LIST_FIRST(&session->object_list),
				true);

	release_session_find_obj_context(session);

	TAILQ_REMOVE(&session->client->session_list, session, link);
	handle_put(&session->client->session_handle_db, session->handle);

	// If no more session, next opened one will simply be Public loggin

	TEE_Free(session);
}

/* ctrl=[session-handle], in=unused, out=unused */
uint32_t entry_ck_token_close_session(uintptr_t tee_session, TEE_Param *ctrl,
				      TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;

	if (!ctrl || in || out || ctrl->memref.size < sizeof(uint32_t))
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	session = sks_handle2session(session_handle, tee_session);
	if (!session)
		return SKS_CKR_SESSION_HANDLE_INVALID;

	close_ck_session(session);

	return SKS_OK;
}

uint32_t entry_ck_token_close_all(uintptr_t tee_session, TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	struct ck_token *token;
	struct pkcs11_session *session;
	struct pkcs11_session *next;
	struct pkcs11_client *client = tee_session2client(tee_session);

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_CKR_SLOT_ID_INVALID;

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next) {
		if (session->token == token)
			close_ck_session(session);
	}

	return SKS_OK;
}

