// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <inttypes.h>
#include <sks_internal_abi.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "sks_helpers.h"

struct sks_object *sks_handle2object(uint32_t handle,
				     struct pkcs11_session *session)
{
	return handle_lookup(&session->object_handle_db, handle);
}

uint32_t sks_object2handle(struct sks_object *obj,
			   struct pkcs11_session *session)
{
	return handle_lookup_handle(&session->object_handle_db, obj);
}

/* Currently handle pkcs11 sessions and tokens */

static struct object_list *get_session_objects(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_get_session_objects(ck_session);
}

static struct ck_token *get_session_token(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_session2token(ck_session);
}

/* Release resources of a non persistent object */
static void cleanup_volatile_obj_ref(struct sks_object *obj)
{
	if (!obj)
		return;

	if (obj->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj->key_handle);

	if (obj->attribs_hdl != TEE_HANDLE_NULL) {
		TEE_CloseObject(obj->attribs_hdl);
	}

	TEE_Free(obj->attributes);
	TEE_Free(obj->uuid);
	TEE_Free(obj);
}


/* Release resources of a persistent object including volatile resources */
void cleanup_persistent_object(struct sks_object *obj,
				      struct ck_token *token)
{
	TEE_Result res;

	if (!obj)
		return;

	/* Open handle with write properties to destroy the object */
	if (obj->attribs_hdl != TEE_HANDLE_NULL) {
		TEE_CloseObject(obj->attribs_hdl);
	}

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj->uuid, sizeof(TEE_UUID),
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&obj->attribs_hdl);
	assert(!res);
	if (res)
		goto out;

	TEE_CloseAndDeletePersistentObject1(obj->attribs_hdl);

out:
	obj->attribs_hdl = TEE_HANDLE_NULL;
	destroy_object_uuid(token, obj);

	LIST_REMOVE(obj, link);

	cleanup_volatile_obj_ref(obj);
}

/*
 * destroy_object - destroy an SKS object
 *
 * @session - session requesting object destruction
 * @object - reference to the sks object
 * @session_object_only - true is only session object shall be destroyed
 */
void destroy_object(struct pkcs11_session *session,
			  struct sks_object *obj,
			  bool session_only)
{
#ifdef DEBUG
	trace_attributes("[destroy]", obj->attributes);
	if (obj->uuid)
		MSG_RAW("[destroy] obj uuid %pUl", (void *)obj->uuid);
#endif

	/* Remove from session list only if was published */
	if (obj->link.le_next || obj->link.le_prev)
		LIST_REMOVE(obj, link);

	if (session_only) {
		/* Destroy object due to session closure */
		handle_put(&session->object_handle_db,
			   sks_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);

		return;
	}

	/* Destroy target object (persistent or not) */
	if (get_bool(obj->attributes, SKS_CKA_TOKEN)) {
		assert(obj->uuid);
		/* Try twice otherwise panic! */
		if (unregister_persistent_object(session->token, obj->uuid) &&
		    unregister_persistent_object(session->token, obj->uuid))
			TEE_Panic(0);

		cleanup_persistent_object(obj, session->token);
		handle_put(&session->object_handle_db,
			   sks_object2handle(obj, session));
	} else {
		handle_put(&session->object_handle_db,
			   sks_object2handle(obj, session));
		cleanup_volatile_obj_ref(obj);
	}
}

static struct sks_object *create_object_instance(struct sks_attrs_head *head)
{
	struct sks_object *obj = NULL;

	obj = TEE_Malloc(sizeof(struct sks_object), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return NULL;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attribs_hdl = TEE_HANDLE_NULL;
	obj->attributes = head;

	return obj;
}

struct sks_object *create_token_object_instance(struct sks_attrs_head *head,
						TEE_UUID *uuid)
{
	struct sks_object *obj = create_object_instance(head);

	if (!obj)
		return NULL;

	obj->uuid = uuid;

	return obj;
}

/*
 * create_object - create an SKS object from its attributes and value
 *
 * @session - session requesting object creation
 * @attributes - reference to serialized attributes
 * @handle - generated handle for the created object
 */
uint32_t create_object(void *sess, struct sks_attrs_head *head,
		       uint32_t *out_handle)
{
	uint32_t rv = 0;
	TEE_Result res = TEE_SUCCESS;
	struct sks_object *obj = NULL;
	struct pkcs11_session *session = (struct pkcs11_session *)sess;
	uint32_t obj_handle = 0;

#ifdef DEBUG
	trace_attributes("[create]", head);
#endif

	/*
	 * We do not check the key attributes. At this point, key attributes
	 * are expected consistent and reliable.
	 */

	obj = create_object_instance(head);
	if (!obj)
		return SKS_MEMORY;

	/* Create a handle for the object in the session database */
	obj_handle = handle_get(&session->object_handle_db, obj);
	if (!obj_handle) {
		rv = SKS_MEMORY;
		goto bail;
	}

	if (get_bool(obj->attributes, SKS_CKA_TOKEN)) {
		/*
		 * Get an ID for the persistent object
		 * Create the file
		 * Register the object in the persistent database
		 * (move the full sequence to persisent_db.c?)
		 */
		size_t size = attributes_size(obj->attributes);

		rv = create_object_uuid(get_session_token(session), obj);
		if (rv)
			goto bail;

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->uuid, sizeof(TEE_UUID),
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE |
						 TEE_DATA_FLAG_ACCESS_WRITE_META,
						 TEE_HANDLE_NULL,
						 obj->attributes, size,
						 &obj->attribs_hdl);
		if (res) {
			rv = tee2sks_error(res);
			goto bail;
		}

		rv = register_persistent_object(get_session_token(session),
						obj->uuid);
		if (rv)
			goto bail;

		LIST_INSERT_HEAD(&session->token->object_list, obj, link);
	} else {
		rv = SKS_OK;
		LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	}


	*out_handle = obj_handle;

bail:
	if (rv) {
		handle_put(&session->object_handle_db, obj_handle);
		if (get_bool(obj->attributes, SKS_CKA_TOKEN))
			cleanup_persistent_object(obj, session->token);
		else
			cleanup_volatile_obj_ref(obj);
	}

	return rv;
}

uint32_t entry_destroy_object(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out)
{
	struct serialargs ctrlargs;
	uint32_t session_handle = 0;
	uint32_t object_handle = 0;
	struct pkcs11_session *session = NULL;
	struct sks_object *object = NULL;
	uint32_t rv = 0;

	TEE_MemFill(&ctrlargs, 0, sizeof(ctrlargs));

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	session = sks_handle2session(session_handle, tee_session);
	if (!session)
		return SKS_CKR_SESSION_HANDLE_INVALID;

	object = sks_handle2object(object_handle, session);
	if (!object)
		return SKS_BAD_PARAM;

	destroy_object(session, object, false);
	handle_put(&session->object_handle_db, object_handle);

	IMSG("SKSs%" PRIu32 ": destroy object 0x%" PRIx32,
	     session_handle, object_handle);

	return rv;
}

static uint32_t token_obj_matches_ref(struct sks_attrs_head *req_attrs,
				      struct sks_object *obj)
{
	uint32_t rv = 0;

	if (!obj->attributes)
		return SKS_NOT_FOUND;

	if (!attributes_match_reference(obj->attributes, req_attrs))
		return SKS_NOT_FOUND;

	rv = SKS_OK;

	return rv;
}

static void release_find_obj_context(struct pkcs11_session *session,
				     struct pkcs11_find_objects *find_ctx)
{
	size_t idx = 0;

	if (!find_ctx)
		return;

	/* Release handles not yet published to client */
	idx = find_ctx->next;
	if (idx < find_ctx->temp_start)
		idx = find_ctx->temp_start;

	for (;idx < find_ctx->count; idx++)
		handle_put(&session->object_handle_db, find_ctx->handles[idx]);

	TEE_Free(find_ctx->attributes);
	TEE_Free(find_ctx->handles);
	TEE_Free(find_ctx);
}

/*
 * Entry for command SKS_CMD_FIND_OBJECTS_INIT
 */
uint32_t entry_find_objects_init(uintptr_t tee_session, TEE_Param *ctrl,
				 TEE_Param *in, TEE_Param *out)
{
	uint32_t rv = 0;
	struct serialargs ctrlargs;
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;
	struct sks_object_head *template = NULL;
	struct sks_attrs_head *req_attrs = NULL;
	struct sks_object *obj = NULL;
	struct pkcs11_find_objects *find_ctx = NULL;

	TEE_MemFill(&ctrlargs, 0, sizeof(ctrlargs));

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		return rv;

	session = sks_handle2session(session_handle, tee_session);
	if (!session) {
		rv = SKS_CKR_SESSION_HANDLE_INVALID;
		goto bail;
	}

	/* Search objects only if no operation is on-going */
	if (session_is_active(session)) {
		rv = SKS_CKR_OPERATION_ACTIVE;
		goto bail;
	}

	if (session->find_ctx) {
		EMSG("Active object search already in progress");
		rv = SKS_FAILED;
		goto bail;
	}

	/* Must zero init the structure */
	find_ctx = TEE_Malloc(sizeof(*find_ctx), TEE_MALLOC_FILL_ZERO);
	if (!find_ctx) {
		rv = SKS_MEMORY;
		goto bail;
	}

	rv = sanitize_client_object(&req_attrs, template,
				    sizeof(*template) + template->attrs_size);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	switch (get_class(req_attrs)) {
	case SKS_UNDEFINED_ID:
	/* Unspecified class searches among data objects */
	case SKS_CKO_CERTIFICATE:
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
	case SKS_CKO_DATA:
		break;
	default:
		EMSG("Find object of class %s (%u) is not supported",
		     sks2str_class(get_class(req_attrs)),
		     get_class(req_attrs));
		rv = SKS_CKR_ARGUMENTS_BAD;
		goto bail;

	}

	/*
	 * Scan all objects (sessions and persistent ones) and set a list of
	 * candidates that match caller attributes. First scan all current
	 * session objects (that are visible to the session). Then scan all
	 * remaining persistent object for which no session object handle was
	 * published to the client.
	 */

	LIST_FOREACH(obj, &session->object_list, link) {
		uint32_t *handles = NULL;

		rv = check_access_attrs_against_token(session, obj->attributes);
		if (rv)
			continue;

		if (!attributes_match_reference(obj->attributes, req_attrs))
			continue;

		handles = TEE_Realloc(find_ctx->handles,
				      (find_ctx->count + 1) * sizeof(*handles));
		if (!handles) {
			rv = SKS_MEMORY;
			goto bail;
		}
		find_ctx->handles = handles;

		*(find_ctx->handles + find_ctx->count) =
			sks_object2handle(obj, session);
		find_ctx->count++;
	}

	/* Remaining handles are those not yet published by the session */
	find_ctx->temp_start = find_ctx->count;

	LIST_FOREACH(obj, &session->token->object_list, link) {
		uint32_t obj_handle = 0;
		uint32_t *handles = NULL;

		/*
		 * If there are no attributes specified, we return
		 * every object
		 */
		if (req_attrs->attrs_count) {
			rv = token_obj_matches_ref(req_attrs, obj);
			if (rv == SKS_NOT_FOUND)
				continue;
			if (rv != SKS_OK)
				goto bail;
		}

		rv = check_access_attrs_against_token(session, obj->attributes);
		if (rv)
			continue;

		/* Object may not yet be published in the session */
		obj_handle = sks_object2handle(obj, session);
		if (!obj_handle) {
			obj_handle = handle_get(&session->object_handle_db,
						obj);
			if (!obj_handle) {
				rv = SKS_MEMORY;
				goto bail;
			}
		}

		handles = TEE_Realloc(find_ctx->handles,
				      (find_ctx->count + 1) * sizeof(*handles));
		if (!handles) {
			rv = SKS_MEMORY;
			goto bail;
		}

		/* Store object handle for later publishing */
		find_ctx->handles = handles;
		*(handles + find_ctx->count) = obj_handle;
		find_ctx->count++;
	}

	if (rv == SKS_NOT_FOUND)
		rv = SKS_OK;

	/* Save target attributes to search (if needed later) */
	find_ctx->attributes = req_attrs;
	req_attrs = NULL;
	session->find_ctx = find_ctx;
	find_ctx = NULL;
	rv = SKS_OK;

bail:
	TEE_Free(req_attrs);
	TEE_Free(template);
	release_find_obj_context(session, find_ctx);

	return rv;
}

/*
 * Entry for command SKS_CMD_FIND_OBJECTS
 */
uint32_t entry_find_objects(uintptr_t tee_session, TEE_Param *ctrl,
			    TEE_Param *in, TEE_Param *out)
{
	uint32_t rv = 0;
	struct serialargs ctrlargs;
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;
	struct pkcs11_find_objects *ctx = NULL;
	uint32_t *out_handles = NULL;
	size_t out_count = 0;
	size_t count = 0;
	size_t idx = 0;

	TEE_MemFill(&ctrlargs, 0, sizeof(ctrlargs));

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	out_count = out->memref.size / sizeof(uint32_t);
	out_handles = (uint32_t *)(uintptr_t)out->memref.buffer;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	session = sks_handle2session(session_handle, tee_session);
	if (!session)
		return SKS_CKR_SESSION_HANDLE_INVALID;

	ctx = session->find_ctx;

	/*
	 * TODO: should we check again if these handles are valid?
	 */
	if (!ctx)
		return SKS_CKR_OPERATION_NOT_INITIALIZED;

	for (count = 0, idx = ctx->next; idx < ctx->count; idx++, count++) {
		struct sks_object *obj = NULL;

		if (count >= out_count)
			break;

		*(out_handles + count) = *(ctx->handles + idx);
		ctx->next = idx + 1;

		if (idx < session->find_ctx->temp_start)
			continue;

		/* Newly published handles: store in session list */
		obj = handle_lookup(&session->object_handle_db,
				    *(ctx->handles + idx));
		if (!obj)
			TEE_Panic(0);

	}

	/* Update output buffer according the number of handles provided */
	out->memref.size = count * sizeof(uint32_t);

	DMSG("SKSs%" PRIu32 ": finding objects", session_handle);

	return SKS_OK;
}

void release_session_find_obj_context(struct pkcs11_session *session)
{
	release_find_obj_context(session, session->find_ctx);
	session->find_ctx = NULL;
}

/*
 * Entry for command SKS_CMD_FIND_OBJECTS_FINAL
 */
uint32_t entry_find_objects_final(uintptr_t tee_session, TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out)
{
	uint32_t rv = 0;
	struct serialargs ctrlargs;
	uint32_t session_handle = 9;
	struct pkcs11_session *session = NULL;

	TEE_MemFill(&ctrlargs, 0, sizeof(ctrlargs));

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	session = sks_handle2session(session_handle, tee_session);
	if (!session)
		return SKS_CKR_SESSION_HANDLE_INVALID;

	if (!session->find_ctx)
		return SKS_CKR_OPERATION_NOT_INITIALIZED;

	release_session_find_obj_context(session);

	return SKS_OK;
}


/*
 * Entry for command SKS_CMD_GET_OBJECT_SIZE
 */
uint32_t entry_get_object_size(uintptr_t tee_session, TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out)
{
	struct serialargs ctrlargs;
	uint32_t session_handle = 0;
	uint32_t object_handle = 0;
	struct pkcs11_session *session = NULL;
	struct sks_object *object = NULL;
	uint32_t rv = 0;

	TEE_MemFill(&ctrlargs, 0, sizeof(ctrlargs));

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(uint32_t))
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	session = sks_handle2session(session_handle, tee_session);
	if (!session)
		return SKS_CKR_SESSION_HANDLE_INVALID;

	object = sks_handle2object(object_handle, session);
	if (!object)
		return SKS_CKR_OBJECT_HANDLE_INVALID;

	*(uint32_t *)out->memref.buffer = SKS_CK_UNAVAILABLE_INFORMATION;
	out->memref.size = sizeof(uint32_t);

	return rv;
}

/*
 * Entry for command SKS_CMD_GET_ATTRIBUTE_VALUE
 */
uint32_t entry_get_attribute_value(uintptr_t tee_session, TEE_Param *ctrl,
				   TEE_Param *in, TEE_Param *out)
{
	uint32_t rv = 0;
	struct serialargs ctrlargs;
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;
	struct sks_object_head *template = NULL;
	struct sks_object *obj = NULL;
	uint32_t object_handle = 0;
	char *cur = NULL;
	size_t len = 0;
	char *end = NULL;
	bool attr_sensitive = 0;
	bool attr_type_invalid = 0;
	bool buffer_too_small = 0;

	TEE_MemFill(&ctrlargs, 0, sizeof(ctrlargs));

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &object_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		return rv;

	session = sks_handle2session(session_handle, tee_session);
	if (!session) {
		rv = SKS_CKR_SESSION_HANDLE_INVALID;
		goto bail;
	}

	obj = sks_handle2object(object_handle, session);
	if (!obj) {
		rv = SKS_CKR_OBJECT_HANDLE_INVALID;
		goto bail;
	}

	rv = check_access_attrs_against_token(session, obj->attributes);
	if (rv) {
		rv = SKS_CKR_OBJECT_HANDLE_INVALID;
		goto bail;
	}

	/* iterate over attributes and set their values */
	/*
	 * 1. If the specified attribute (i.e., the attribute specified by the
	 * type field) for the object cannot be revealed because the object is
	 * sensitive or unextractable, then the ulValueLen field in that triple
	 * is modified to hold the value CK_UNAVAILABLE_INFORMATION.
	 *
	 * 2. Otherwise, if the specified value for the object is invalid (the
	 * object does not possess such an attribute), then the ulValueLen field
	 * in that triple is modified to hold the value
	 * CK_UNAVAILABLE_INFORMATION.
	 *
	 * 3. Otherwise, if the pValue field has the value NULL_PTR, then the
	 * ulValueLen field is modified to hold the exact length of the
	 * specified attribute for the object.
	 *
	 * 4. Otherwise, if the length specified in ulValueLen is large enough
	 * to hold the value of the specified attribute for the object, then
	 * that attribute is copied into the buffer located at pValue, and the
	 * ulValueLen field is modified to hold the exact length of the
	 * attribute.
	 *
	 * 5. Otherwise, the ulValueLen field is modified to hold the value
	 * CK_UNAVAILABLE_INFORMATION.
	 */
	cur = (char *)template + sizeof(struct sks_object_head);
	end = cur + template->attrs_size;

	for (; cur < end; cur += len) {
		struct sks_attribute_head *cli_ref =
			(struct sks_attribute_head *)(void *)cur;
		struct sks_attribute_head cli_head;
		void *data_ptr = NULL;

		/* Make copy of header so that is aligned properly */
		TEE_MemMove(&cli_head, cli_ref, sizeof(cli_head));

		len = sizeof(*cli_ref) + cli_head.size;

		/* Check 1. */
		if (!attribute_is_exportable(&cli_head, obj)) {
			cli_head.size = SKS_CK_UNAVAILABLE_INFORMATION;
			TEE_MemMove(&cli_ref->size, &cli_head.size,
					sizeof(cli_head.size));
			attr_sensitive = 1;
			continue;
		}

		/* Get real data pointer from template data */
		data_ptr = cli_head.size ? cli_ref->data : NULL;

		/*
		 * We assume that if size is 0, pValue was NULL, so we return
		 * the size of the required buffer for it (3., 4.)
		 */
		rv = get_attribute(obj->attributes, cli_head.id, data_ptr,
				   &cli_head.size);
		/* Check 2. */
		switch (rv) {
		case SKS_OK:
			break;
		case SKS_NOT_FOUND:
			cli_head.size = SKS_CK_UNAVAILABLE_INFORMATION;
			attr_type_invalid = 1;
			break;
		case SKS_SHORT_BUFFER:
			if (data_ptr)
				buffer_too_small = 1;
			break;
		default:
			rv = SKS_ERROR;
			goto bail;
		}

		TEE_MemMove(&cli_ref->size, &cli_head.size,
				sizeof(cli_head.size));
	}

	/*
	 * If case 1 applies to any of the requested attributes, then the call
	 * should return the value CKR_ATTRIBUTE_SENSITIVE. If case 2 applies to
	 * any of the requested attributes, then the call should return the
	 * value CKR_ATTRIBUTE_TYPE_INVALID. If case 5 applies to any of the
	 * requested attributes, then the call should return the value
	 * CKR_BUFFER_TOO_SMALL. As usual, if more than one of these error codes
	 * is applicable, Cryptoki may return any of them. Only if none of them
	 * applies to any of the requested attributes will CKR_OK be returned.
	 */

	rv = SKS_OK;
	if (attr_sensitive)
		rv = SKS_CKR_ATTRIBUTE_SENSITIVE;
	if (attr_type_invalid)
		rv = SKS_CKR_ATTRIBUTE_TYPE_INVALID;
	if (buffer_too_small)
		rv = SKS_CKR_BUFFER_TOO_SMALL;

	/* Move updated template to out buffer */
	TEE_MemMove(out->memref.buffer, template, out->memref.size);

	DMSG("SKSs%" PRIu32 ": get attributes 0x%" PRIx32,
	     session_handle, object_handle);

bail:
	TEE_Free(template);
	template = NULL;

	return rv;
}
