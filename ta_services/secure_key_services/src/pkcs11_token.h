/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */
#ifndef __SKS_PKCS11_TOKEN_H__
#define __SKS_PKCS11_TOKEN_H__

#include <sys/queue.h>
#include <tee_internal_api.h>

#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"

/* Hard coded description */
#define SKS_CRYPTOKI_TOKEN_LABEL		"op-tee pkcs#11 token (dev...)"
#define SKS_CRYPTOKI_TOKEN_MANUFACTURER		"Linaro"
#define SKS_CRYPTOKI_TOKEN_MODEL		"OP-TEE SKS TA"
#define SKS_CRYPTOKI_TOKEN_SERIAL_NUMBER	"0000000000000000"
#define SKS_CRYPTOKI_TOKEN_HW_VERSION		{ 0, 0 }
#define SKS_CRYPTOKI_TOKEN_FW_VERSION		{ 0, 0 }

#define SKS_CRYPTOKI_SLOT_DESCRIPTION		"OP-TEE SKS TA"
#define SKS_CRYPTOKI_SLOT_MANUFACTURER		SKS_CRYPTOKI_TOKEN_MANUFACTURER
#define SKS_CRYPTOKI_SLOT_HW_VERSION		SKS_CRYPTOKI_TOKEN_HW_VERSION
#define SKS_CRYPTOKI_SLOT_FW_VERSION		SKS_CRYPTOKI_TOKEN_FW_VERSION

#define PADDED_STRING_COPY(_dst, _src) \
	do { \
		TEE_MemFill((char *)(_dst), ' ', sizeof(_dst)); \
		TEE_MemMove((char *)(_dst), (_src), \
			    MIN(strlen((char *)(_src)), sizeof(_dst))); \
	} while (0)

enum pkcs11_token_state {
	PKCS11_TOKEN_RESET = 0,
	PKCS11_TOKEN_READ_WRITE,
	PKCS11_TOKEN_READ_ONLY,
};

enum pkcs11_session_state {
	PKCS11_SESSION_RESET = 0,
	PKCS11_SESSION_PUBLIC_READ_WRITE,
	PKCS11_SESSION_PUBLIC_READ_ONLY,
	PKCS11_SESSION_USER_READ_WRITE,
	PKCS11_SESSION_USER_READ_ONLY,
	PKCS11_SESSION_SO_READ_WRITE,
};

TAILQ_HEAD(client_list, pkcs11_client);
TAILQ_HEAD(session_list, pkcs11_session);

#define SKS_MAX_USERS			2
#define SKS_TOKEN_PIN_SIZE		128

/*
 * Persistent state of the token
 *
 * @version - currently unused...
 * @label - pkcs11 formatted token label, set by client
 * @flags - pkcs11 token flags
 * @so_pin_count - counter on security officer login failure
 * @so_pin_size - byte size of the provisionned SO PIN
 * @so_pin - stores the SO PIN
 * @user_pin_count - counter on user login failure
 * @user_pin_size - byte size of the provisionned user PIN
 * @user_pin - stores the user PIN
 */
struct token_persistent_main {
	uint32_t version;

	uint8_t label[SKS_TOKEN_LABEL_SIZE];
	uint32_t flags;

	uint32_t so_pin_count;
	uint32_t so_pin_size;
	uint8_t so_pin[SKS_TOKEN_PIN_SIZE];

	uint32_t user_pin_count;
	uint32_t user_pin_size;
	uint8_t user_pin[SKS_TOKEN_PIN_SIZE];
};

/*
 * Persistent objects in the token
 *
 * @count - number of object stored in the token
 * @uudis - start of object references/UUIDs (@count items)
 */
struct token_persistent_objs {
	uint32_t count;
	TEE_UUID uuids[];
};

/*
 * Runtime state of the token, complies with pkcs11
 *
 * @login_state - Pkcs11 login is public, user, SO or custom
 * @db_hld - TEE handle on the persistent database object or TEE_HANDLE_NULL
 * @pin_hld - TEE handles on PIN ciphering keys
 * @db_main - Volatile copy of the persistent main database
 * @session_count - Counter for opened Pkcs11 sessions
 * @rw_session_count - Count for opened Pkcs11 read/write sessions
 * @session_state - Login state of the token
 * @session_list - Head of the list of the sessions owned by the token
 */
struct ck_token {
	enum pkcs11_token_state state;
	uint32_t session_count;
	uint32_t rw_session_count;

	struct object_list object_list;

	TEE_ObjectHandle db_hdl;	/* Opened handle to persistent database */
	TEE_ObjectHandle pin_hdl[SKS_MAX_USERS];	/* Opened handle to PIN keys */
	struct token_persistent_main *db_main;		/* Copy persistent database */
	struct token_persistent_objs *db_objs;		/* Copy persistent database */
};

/*
 * A session can enter a processing state (encrypt, decrypt, disgest, ...
 * only from the inited state. A sesion must return the the inited
 * state (from a processing finalization request) before entering another
 * processing state.
 */
enum pkcs11_proc_state {
	PKCS11_SESSION_READY = 0,		/* No active processing/operation */
	PKCS11_SESSION_ENCRYPTING,
	PKCS11_SESSION_DECRYPTING,
	PKCS11_SESSION_DIGESTING,
	PKCS11_SESSION_DIGESTING_ENCRYPTING,	/* case C_DigestEncryptUpdate */
	PKCS11_SESSION_DECRYPTING_DIGESTING,	/* case C_DecryptDigestUpdate */
	PKCS11_SESSION_SIGNING,
	PKCS11_SESSION_SIGNING_ENCRYPTING,	/* case C_SignEncryptUpdate */
	PKCS11_SESSION_VERIFYING,
	PKCS11_SESSION_DECRYPTING_VERIFYING,	/* case C_DecryptVerifyUpdate */
	PKCS11_SESSION_SIGNING_RECOVER,
	PKCS11_SESSION_VERIFYING_RECOVER,
};

/*
 * Pkcs11 objects serach context
 *
 * @attributes - matching attributes list searched (null if no search)
 * @count - number of matching handle found
 * @handles - array of handle of matching objects (published handles)
 * @next - index of the next object handle to return to FindObject
 * @temp_start - index of the trailing not yet published handles
 */
struct pkcs11_find_objects {
	void *attributes;
	size_t count;
	uint32_t *handles;
	size_t next;
	size_t temp_start;
};

/*
 * Structure tracking client applications
 *
 * TODO: rename pkcs11_client into sks_client
 *
 * @link - chained list of registered client applications
 * @sessions - list of the PKCS11 sessions opened by the client application
 */
struct pkcs11_client {
	TAILQ_ENTRY(pkcs11_client) link;
	struct session_list session_list;
	struct handle_db session_handle_db;
};

/*
 * Structure tracking the PKCS#11 sessions
 *
 * @link - list of the session belowing to a client
 * @tee_session - TEE session handle used by PKCS11 session client
 * @client - client the session belongs to (FIXME: redondant with tee_session)
 * @token - token this session belongs to
 * @handle - identifier of the session published to the client
 * @object_list - entry of the session objects list
 * @object_handle_db - database for object handles published by the session
 * @state - R/W SO, R/W user, RO user, R/W public, RO public.
 * @processing - ongoing active processing function or ready state
 * @processing_updated - true once an active operation is updated
 * @processing_relogged - true once client logged since last operation update
 * @processing_always_authen - true if user need to login before each use
 * @proc_id - SKS ID of the active processing
 * @proc_params - parameters saved in memory for the active processing
 * @tee_op_handle - handle on active crypto operation or TEE_HANDLE_NULL
 * @find_ctx - point to active search context (null if no active search)
 */
struct pkcs11_session {
	TAILQ_ENTRY(pkcs11_session) link;
	uintptr_t tee_session;
	struct pkcs11_client *client;
	struct ck_token *token;
	uint32_t handle;
	struct object_list object_list;
	struct handle_db object_handle_db;
	enum pkcs11_session_state state;
	enum pkcs11_proc_state processing;
	bool processing_updated;
	bool processing_relogged;
	bool processing_always_authen;
	// TODO: end time for object usage
	uint32_t proc_id;
	void *proc_params;
	TEE_OperationHandle tee_op_handle;
	struct pkcs11_find_objects *find_ctx;
};

/* Initialize static token instance(s) from default/persistent database */
int pkcs11_init(void);
void pkcs11_deinit(void);

/* Return token instance from token identifier */
struct ck_token *get_token(unsigned int token_id);

/* Return token identified from token instance address */
unsigned int get_token_id(struct ck_token *token);

/* Initialize target token database */
struct ck_token *init_token_db(unsigned int token_id);

/* Persistent database update */
int update_persistent_db(struct ck_token *token, size_t offset, size_t size);
void close_persistent_db(struct ck_token *token);

/* Token persistent objects */
uint32_t create_object_uuid(struct ck_token *token, struct sks_object *obj);
void destroy_object_uuid(struct ck_token *token, struct sks_object *obj);
uint32_t unregister_persistent_object(struct ck_token *token, TEE_UUID *uuid);
uint32_t register_persistent_object(struct ck_token *token, TEE_UUID *uuid);
uint32_t get_persistent_objects_list(struct ck_token *token,
				     TEE_UUID *array, size_t *size);

/*
 * Pkcs11 session support
 */
struct pkcs11_client *tee_session2client(uintptr_t tee_session);
uintptr_t register_client(void);
void unregister_client(uintptr_t tee_session);

void ck_token_close_tee_session(uintptr_t tee_session);
struct pkcs11_session *sks_handle2session(uint32_t handle,
					  uintptr_t tee_session);

void reset_processing_state(struct pkcs11_session *session);
int set_processing_state(struct pkcs11_session *session,
			 enum processing_func function,
			 struct sks_object *obj1, struct sks_object *obj2);

bool pkcs11_session_is_read_write(struct pkcs11_session *session);
bool pkcs11_session_is_public(struct pkcs11_session *session);
bool pkcs11_session_is_user(struct pkcs11_session *session);
bool pkcs11_session_is_security_officer(struct pkcs11_session *session);

static inline
struct object_list *pkcs11_get_session_objects(struct pkcs11_session *session)
{
	return &session->object_list;
}

static inline
struct ck_token *pkcs11_session2token(struct pkcs11_session *session)
{
	return session->token;
}

/*
 * Entry point for the TA commands
 */
uint32_t entry_ck_slot_list(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t entry_ck_slot_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
uint32_t entry_ck_token_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

uint32_t entry_ck_token_initialize(TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out);

uint32_t entry_ck_token_mecha_ids(TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out);

uint32_t entry_ck_token_mecha_info(TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out);

uint32_t entry_ck_token_ro_session(uintptr_t teesess, TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out);
uint32_t entry_ck_token_rw_session(uintptr_t teesess, TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out);
uint32_t entry_ck_token_close_session(uintptr_t teesess, TEE_Param *ctrl,
				      TEE_Param *in, TEE_Param *out);
uint32_t entry_ck_token_close_all(uintptr_t teesess, TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out);

uint32_t entry_init_pin(uintptr_t tee_session, TEE_Param *ctrl,
			TEE_Param *in, TEE_Param *out);
uint32_t entry_set_pin(uintptr_t tee_session, TEE_Param *ctrl,
		       TEE_Param *in, TEE_Param *out);
uint32_t entry_login(uintptr_t tee_session, TEE_Param *ctrl,
		     TEE_Param *in, TEE_Param *out);
uint32_t entry_logout(uintptr_t tee_session, TEE_Param *ctrl,
		      TEE_Param *in, TEE_Param *out);

#endif /*__SKS_PKCS11_TOKEN_H__*/
