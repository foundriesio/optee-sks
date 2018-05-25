/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
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

/* Provide 3 slots/tokens */
#define TOKEN_COUNT	3

/* Static allocation of tokens runtime instances (reset to 0 at load) */
struct ck_token ck_token[TOKEN_COUNT];

static struct handle_db session_handle_db = HANDLE_DB_INITIALIZER;

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

static int pkcs11_token_init(unsigned int id)
{
	struct ck_token *token = init_token_db(id);

	if (!token)
		return 1;

	if (token->login_state != PKCS11_TOKEN_STATE_INVALID)
		return 0;

	/* Initialize the token runtime state */
	token->login_state = PKCS11_TOKEN_STATE_PUBLIC_SESSIONS;
	token->session_state = PKCS11_TOKEN_STATE_SESSION_NONE;
	TAILQ_INIT(&token->session_list);
	TEE_MemFill(&token->session_handle_db, 0,
		    sizeof(token->session_handle_db));

	return 0;
}

int pkcs11_init(void)
{
	unsigned int id;

	for (id = 0; id < TOKEN_COUNT; id++)
		if (pkcs11_token_init(id))
			return 1;

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
	if (!session->readwrite)
		return false;

	if (session->token->session_state ==
	    PKCS11_TOKEN_STATE_SESSION_READ_ONLY)
		return false;

	switch (session->token->login_state) {
	case PKCS11_TOKEN_STATE_INVALID:
	case PKCS11_TOKEN_STATE_SECURITY_OFFICER:
		return false;
	case PKCS11_TOKEN_STATE_PUBLIC_SESSIONS:
	case PKCS11_TOKEN_STATE_USER_SESSIONS:
	case PKCS11_TOKEN_STATE_CONTEXT_SPECIFIC:
		break;
	default:
		TEE_Panic(0);
	}

	return true;
}

struct pkcs11_session *sks_handle2session(uint32_t handle)
{
	return handle_lookup(&session_handle_db, (int)handle);
}

/*
 * PKCS#11 expects an session must finalize (or cancel) an operation
 * before starting a new one.
 *
 * enum pkcs11_session_processing provides the valid operation states for a
 * PKCS#11 session.
 *
 * set_pkcs_session_processing_state() changes the session operation state.
 *
 * check_pkcs_session_processing_state() checks the session is in the expected
 * operation state.
 */
int set_pkcs_session_processing_state(struct pkcs11_session *pkcs_session,
				      enum pkcs11_session_processing state)
{
	if (!pkcs_session)
		return 1;

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

int check_pkcs_session_processing_state(struct pkcs11_session *pkcs_session,
					enum pkcs11_session_processing state)
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
		return SKS_INVALID_SLOT;

	if (token->db_main->flags & SKS_TOKEN_SO_PIN_LOCKED) {
		IMSG("Token SO PIN is locked");
		return SKS_PIN_LOCKED;
	}

	if (!TAILQ_EMPTY(&token->session_list)) {
		IMSG("SO cannot log in, pending session(s)");
		return SKS_CK_SESSION_PENDING;
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
		token->db_main->flags |= SKS_TOKEN_SO_PIN_FAILURE;
		token->db_main->so_pin_count++;

		if (token->db_main->so_pin_count == 6)
			token->db_main->flags |= SKS_TOKEN_SO_PIN_LAST;
		if (token->db_main->so_pin_count == 7)
			token->db_main->flags |= SKS_TOKEN_SO_PIN_LOCKED;

		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      flags),
				     sizeof(token->db_main->flags));
		update_persistent_db(token,
				     offsetof(struct token_persistent_main,
					      so_pin_count),
				     sizeof(token->db_main->so_pin_count));

		TEE_Free(cpin);
		return SKS_PIN_INCORRECT;
	}

	token->db_main->flags &= ~(SKS_TOKEN_SO_PIN_FAILURE |
				   SKS_TOKEN_SO_PIN_LAST);
	token->db_main->so_pin_count = 0;

inited:
	TEE_MemMove(token->db_main->label, label, SKS_TOKEN_LABEL_SIZE);
	token->db_main->flags |= SKS_TOKEN_INITED;

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
	struct sks_ck_slot_info info;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(struct sks_ck_slot_info)) {
		out->memref.size = sizeof(struct sks_ck_slot_info);
		return SKS_SHORT_BUFFER;
	}

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

	TEE_MemFill(&info, 0, sizeof(info));

	PADDED_STRING_COPY(info.slotDescription, desc);
	PADDED_STRING_COPY(info.manufacturerID, manuf);

	info.flags |= SKS_TOKEN_PRESENT;
	info.flags |= SKS_TOKEN_REMOVABLE;
	info.flags &= ~SKS_TOKEN_HW;

	TEE_MemMove(&info.hardwareVersion, &hwver, sizeof(hwver));
	TEE_MemMove(&info.firmwareVersion, &fwver, sizeof(fwver));

	out->memref.size = sizeof(struct sks_ck_slot_info);
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
	struct sks_ck_token_info info;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(struct sks_ck_token_info)) {
		out->memref.size = sizeof(struct sks_ck_token_info);
		return SKS_SHORT_BUFFER;
	}

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

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
		SKS_PROC_AES_ECB_NOPAD,
		SKS_PROC_AES_CBC_NOPAD,
		SKS_PROC_AES_CBC_PAD,
		SKS_PROC_AES_CTS,
		SKS_PROC_AES_CTR,
		SKS_PROC_AES_GCM,
		SKS_PROC_AES_CCM,
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
		return SKS_INVALID_SLOT;

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
	struct sks_ck_mecha_info info;

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
		return SKS_INVALID_SLOT;

	TEE_MemFill(&info, 0, sizeof(info));

	/* TODO: full list of supported algorithm/mechanism */
	switch (type) {
	case SKS_PROC_AES_GCM:
	case SKS_PROC_AES_CCM:
		info.flags |= SKS_PROC_SIGN | SKS_PROC_VERIFY;
	case SKS_PROC_AES_ECB_NOPAD:
	case SKS_PROC_AES_CBC_NOPAD:
	case SKS_PROC_AES_CBC_PAD:
	case SKS_PROC_AES_CTS:
	case SKS_PROC_AES_CTR:
		info.flags |= SKS_PROC_ENCRYPT | SKS_PROC_DECRYPT |
			     SKS_PROC_WRAP | SKS_PROC_UNWRAP | SKS_PROC_DERIVE;
		info.min_key_size =  128;
		info.max_key_size =  256;
		break;

	default:
		break;
	}

	out->memref.size = sizeof(info);
	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return SKS_OK;
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
static uint32_t ck_token_session(uintptr_t teesess, TEE_Param *ctrl,
				 TEE_Param *in, TEE_Param *out, bool readonly)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	struct ck_token *token;
	struct pkcs11_session *session;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

	if (readonly &&
	    token->login_state == PKCS11_TOKEN_STATE_SECURITY_OFFICER &&
	    token->session_state == PKCS11_TOKEN_STATE_SESSION_READ_WRITE)
		return SKS_CK_SO_IS_LOGGED_READ_WRITE;

	session = TEE_Malloc(sizeof(*session), 0);
	if (!session)
		return SKS_MEMORY;

	session->handle = handle_get(&session_handle_db, session);
	session->tee_session = teesess;
	session->processing = PKCS11_SESSION_READY;
	session->tee_op_handle = TEE_HANDLE_NULL;
	session->readwrite = !readonly;
	session->token = token;
	session->proc_id = SKS_UNDEFINED_ID;
	LIST_INIT(&session->object_list);

	if (readonly)
		token->session_state = PKCS11_TOKEN_STATE_SESSION_READ_ONLY;

	TAILQ_INSERT_HEAD(&token->session_list, session, link);

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
	struct ck_token *token = session->token;

	(void)handle_put(&session_handle_db, session->handle);

	if (session->tee_op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(session->tee_op_handle);

	while (!LIST_EMPTY(&session->object_list))
		destroy_object(session, LIST_FIRST(&session->object_list),
				true);

	release_session_find_obj_context(session);

	TAILQ_REMOVE(&token->session_list, session, link);

	/* Closing last read-only session switches token to read/write state */
	if (!session->readwrite) {
		struct pkcs11_session *sess;
		bool last_ro = true;
		bool last = true;

		TAILQ_FOREACH(sess, &session->token->session_list, link) {
			last = false;

			if (sess->readwrite)
				continue;

			last_ro = false;
		}

		if (last)
		    session->token->session_state =
					PKCS11_TOKEN_STATE_SESSION_NONE;
		else if (last_ro)
		    session->token->session_state =
					PKCS11_TOKEN_STATE_SESSION_READ_WRITE;
	}

	if (TAILQ_EMPTY(&session->token->session_list))
		session->token->login_state =
					PKCS11_TOKEN_STATE_PUBLIC_SESSIONS;

	TEE_Free(session);
}

/* ctrl=[session-handle], in=unused, out=unused */
uint32_t entry_ck_token_close_session(uintptr_t teesess, TEE_Param *ctrl,
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

	session = sks_handle2session(session_handle);
	if (!session || session->tee_session != teesess)
		return SKS_INVALID_SESSION;

	close_ck_session(session);

	return SKS_OK;
}

uint32_t entry_ck_token_close_all(uintptr_t teesess __unused, TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rv)
		return rv;

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

	while (!TAILQ_EMPTY(&token->session_list))
		close_ck_session(TAILQ_FIRST(&token->session_list));

	return SKS_OK;
}

/*
 * Parse all tokens and all sessions. Close all sessions that are relying
 * on the target TEE session ID which is being closed by caller.
 */
void ck_token_close_tee_session(uintptr_t tee_session)
{
	struct ck_token *token;
	struct pkcs11_session *session;
	struct pkcs11_session *next;
	int n;

	for (n = 0; n < TOKEN_COUNT; n++) {
		token = get_token(n);
		if (!token)
			continue;

		TAILQ_FOREACH_SAFE(session, &token->session_list, link, next) {
			if (session->tee_session == tee_session)
				close_ck_session(session);
		}
	}
}
