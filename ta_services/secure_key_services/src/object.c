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

/*
 * A database for the objects loaded in the TA.
 * TODO: move object db to session or token.
 */
static struct handle_db object_handle_db = HANDLE_DB_INITIALIZER;

struct sks_object *sks_handle2object(uint32_t handle,
				     struct pkcs11_session *session)
{
	struct sks_object *obj = handle_lookup(&object_handle_db, handle);

	if (obj->session_owner != session)
		return NULL;

	return obj;
}

/* Currently handle pkcs11 sessions and tokens */

static inline struct object_list *get_session_objects(void *session)
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

static struct ck_token *get_object_token(struct sks_object *obj)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = obj->session_owner;

	return pkcs11_session2token(ck_session);
}

/* Release resources of a non persistent object */
static void cleanup_volatile_obj_ref(struct sks_object *obj)
{
	if (!obj)
		return;

	if (obj->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj->key_handle);

	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

	handle_put(&object_handle_db, obj->client_handle);

	TEE_Free(obj->attributes);
	TEE_Free(obj->uuid);
	TEE_Free(obj);
}

static void release_object_from_handle(uint32_t handle)
{
	struct sks_object *obj = handle_lookup(&object_handle_db, handle);

	cleanup_volatile_obj_ref(obj);
}

/* Release resources of a persistent object including volatile resources */
static void cleanup_persistent_object(struct sks_object *obj)
{
	TEE_Result res;

	if (!obj)
		return;

	/* Open handle with write properties to destroy the object */
	if (obj->attribs_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(obj->attribs_hdl);

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
	destroy_object_uuid(get_session_token(obj->session_owner), obj);
	cleanup_volatile_obj_ref(obj);
}

/*
 * Destroy an object
 *
 * @session - session requesting object destruction
 * @obj - object to destroy
 * @session_only - Destroy only the session resources
 */
uint32_t destroy_object(struct pkcs11_session *session,
			  struct sks_object *obj,
			  bool session_only)
{
#ifdef DEBUG
	trace_attributes("[destroy]", obj->attributes);
	if (obj->uuid)
		MSG_RAW("[destroy] obj uuid %pUl", (void *)obj->uuid);
#endif

	/*
	 * Objects are reachable only from their context.
	 * We only support pkcs11 session for now: check object token id.
	 */
	if (get_object_token(obj) != session->token)
		return SKS_BAD_PARAM;

	/* Non persistent object are reachable from their session */
	if (obj->attribs_hdl == TEE_HANDLE_NULL &&
	    obj->session_owner != session)
		return SKS_CKR_OBJECT_HANDLE_INVALID;

	/* Remove from session list only if was published */
	if (obj->link.le_next || obj->link.le_prev)
		LIST_REMOVE(obj, link);

	if (session_only) {
		/* Destroy object due to session closure */
		cleanup_volatile_obj_ref(obj);
		return SKS_OK;
	}

	/* Destroy target object (persistent or not) */
	if (get_bool(obj->attributes, SKS_CKA_TOKEN)) {
		assert(obj->uuid);
		if (unregister_persistent_object(get_object_token(obj),
						  obj->uuid))
			TEE_Panic(0);

		cleanup_persistent_object(obj);
	} else {
		cleanup_volatile_obj_ref(obj);
	}

	return SKS_OK;
}

static struct sks_object *create_object_instance(void *session,
						 struct sks_attrs_head *head)
{
	struct sks_object *obj;
	uint32_t obj_handle;

	obj = TEE_Malloc(sizeof(struct sks_object), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return NULL;

	obj_handle = handle_get(&object_handle_db, obj);
	if (!obj_handle) {
		TEE_Free(obj);
		return NULL;
	}

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attribs_hdl = TEE_HANDLE_NULL;
	obj->attributes = head;
	obj->client_handle = obj_handle;
	obj->session_owner = session;

	return obj;
}

uint32_t create_object(void *session, struct sks_attrs_head *head,
		       uint32_t *out_handle)
{
	uint32_t rv;
	TEE_Result res = TEE_SUCCESS;
	struct sks_object *obj;

#ifdef DEBUG
	trace_attributes("[create]", head);
#endif

	/*
	 * We do not check the key attributes. At this point, key attributes
	 * are expected consistent and reliable.
	 */

	obj = create_object_instance(session, head);
	if (!obj)
		return SKS_MEMORY;

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
	} else {
		rv = SKS_OK;
	}

	LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	*out_handle = obj->client_handle;

bail:
	if (rv) {
		if (get_bool(obj->attributes, SKS_CKA_TOKEN))
			cleanup_persistent_object(obj);
		else
			cleanup_volatile_obj_ref(obj);
	}

	return rv;
}

uint32_t entry_destroy_object(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out)
{
	struct serialargs ctrlargs;
	uint32_t session_handle;
	uint32_t object_handle;
	struct pkcs11_session *session;
	struct sks_object *object;
	uint32_t rv;

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
	if (!object || object->session_owner != session)
		return SKS_BAD_PARAM;

	return destroy_object(session, object, false);
}

/* Init the list of the persistent UUIDs currently stored */
static uint32_t init_plist(struct pkcs11_session *session,
			   TEE_UUID **uuids, size_t *count)
{
	size_t size = 0;
	TEE_UUID *ptr;
	uint32_t rv;

	rv = get_persistent_objects_list(session->token, NULL, &size);

	if (rv == SKS_OK && !size) {
		*count = 0;
		*uuids = NULL;
		return SKS_OK;
	}

	if (rv != SKS_SHORT_BUFFER)
		return SKS_ERROR;

	ptr = TEE_Malloc(size, 0);
	if (!ptr)
		return SKS_MEMORY;

	rv = get_persistent_objects_list(session->token, ptr, &size);
	if (rv) {
		TEE_Free(ptr);
	} else {
		assert(!(size % sizeof(TEE_UUID)));
		*count = size / sizeof(TEE_UUID);
		*uuids = ptr;
	}

	return rv;
}

/* Remove UUID from the list of the persistent UUIDs that match find request */
static void remove_from_plist(TEE_UUID *uuid, TEE_UUID *puuids, size_t *count)
{
	size_t idx = *count;

	if (!uuid)
		return;

	while (idx--) {
		if (!TEE_MemCompare(uuid, puuids + idx, sizeof(TEE_UUID))) {
			TEE_MemMove(puuids + idx, puuids + idx + 1,
				    (*count - idx - 1) * sizeof(TEE_UUID));
			(*count)--;

			return;
		}
	}
}

static uint32_t token_obj_matches_reference(struct sks_attrs_head *req_attrs,
					    TEE_UUID *uuid,
					    TEE_ObjectHandle *tee_hdl,
					    struct sks_attrs_head **obj_attrs)
{
	uint32_t rv;
	TEE_Result res;
	TEE_ObjectHandle hdl;
	TEE_ObjectInfo info;
	struct sks_attrs_head *attr = NULL;
	uint32_t read_bytes;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					uuid, sizeof(TEE_UUID),
					TEE_DATA_FLAG_ACCESS_READ,
					&hdl);
	if (res)
		return tee2sks_error(res);

	res = TEE_GetObjectInfo1(hdl, &info);
	if (res) {
		rv = tee2sks_error(res);
		goto bail;
	}

	attr = TEE_Malloc(info.dataSize, 0);
	if (!attr) {
		rv = SKS_MEMORY;
		goto bail;
	}

	res = TEE_ReadObjectData(hdl, attr, info.dataSize, &read_bytes);
	if (!res)
		res = TEE_SeekObjectData(hdl, 0, TEE_DATA_SEEK_SET);
	if (res) {
		rv = tee2sks_error(res);
		goto bail;
	}
	if (read_bytes != info.dataSize) {
		rv = SKS_ERROR;
		goto bail;
	}

	if (!attributes_match_reference(attr, req_attrs)) {
		rv = SKS_NOT_FOUND;
		goto bail;
	}

	*obj_attrs = attr;
	attr = NULL;
	*tee_hdl = hdl;
	hdl = TEE_HANDLE_NULL;
	rv = SKS_OK;

bail:
	TEE_Free(attr);
	TEE_CloseObject(hdl);

	return rv;
}

static void release_find_obj_context(struct pkcs11_find_objects *find_ctx)
{
	size_t idx;

	if (!find_ctx)
		return;

	/* Release all non published handles */
	idx = find_ctx->next;
	if (idx < find_ctx->temp_start)
		idx = find_ctx->temp_start;

	for (;idx < find_ctx->count; idx++)
		release_object_from_handle(find_ctx->handles[idx]);

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
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_object_head *template = NULL;
	struct sks_attrs_head *req_attrs = NULL;
	struct sks_object *obj = NULL;
	struct pkcs11_find_objects *find_ctx = NULL;
	TEE_UUID *uuids_tbl = NULL;
	size_t uuids_count = 0;

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

	/*
	 * Can search object only in ready state and no already active search
	 * FIXME: not clear if C_FindObjects can be called while a processing
	 * is active. It seems not... but to be confirmed!
	 */
	if (check_processing_state(session, PKCS11_SESSION_READY)) {
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

	/*
	 * TODO: is class is HW_OBJECT or PROCESSING, we must look from HW
	 * features or processing capabilities, not standard secure a object.
	 */

	/*
	 * Scan all objects (sessions and persistent ones) and set a list of
	 * candidates that match caller attributes
	 *
	 * - scan all current session session objects
	 *   (if public session: reject private objects)
	 * - then scan all persistent object
	 *   (if there is already a handle in the session, skip it)
	 *
	 *
	 * TODO: attrbiute class is SKS_PROCESS => search only mechanisms.
	 * TODO: attrbiute class is SKS_HW_FEATURE => search only HW objects.
	 */
	rv = init_plist(session, &uuids_tbl, &uuids_count);
	if (rv)
		goto bail;

	LIST_FOREACH(obj, &session->object_list, link) {
		uint32_t *handles;

		remove_from_plist(obj->uuid, uuids_tbl, &uuids_count);

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

		*(find_ctx->handles + find_ctx->count) = obj->client_handle;
		find_ctx->count++;
	}

	/* Trailer handles are those not yet published by the session */
	find_ctx->temp_start = find_ctx->count;

	while (uuids_count--) {
		struct sks_attrs_head *obj_attrs = NULL;
		TEE_ObjectHandle tee_hdl = TEE_HANDLE_NULL;
		uint32_t *handles;
		TEE_UUID *uuid;

		rv = token_obj_matches_reference(req_attrs,
						 uuids_tbl + uuids_count,
						 &tee_hdl, &obj_attrs);
		if (rv == SKS_NOT_FOUND)
			continue;
		if (rv != SKS_OK)
			goto bail;

		uuid = TEE_Malloc(sizeof(TEE_UUID), 0);
		handles = TEE_Realloc(find_ctx->handles,
				      (find_ctx->count + 1) * sizeof(*handles));
		if (!uuid || !handles) {
			rv = SKS_MEMORY;
			TEE_Free(uuid);
			TEE_Free(handles);
			goto bail;
		}

		/* Allocate a temporary handle: will free if not published */
		obj = create_object_instance(session, obj_attrs);
		if (!obj) {
			rv = SKS_MEMORY;
			TEE_Free(uuid);
			TEE_Free(handles);
			goto bail;
		}

		TEE_MemMove(uuid, uuids_tbl + uuids_count, sizeof(TEE_UUID));
		obj->uuid = uuid;
		obj->attribs_hdl = tee_hdl;

		/* Store object handle for later publishing */
		find_ctx->handles = handles;
		*(handles + find_ctx->count) = obj->client_handle;
		find_ctx->count++;
	}

	/* Save target attributes to search (if needed later) */
	find_ctx->attributes = req_attrs;
	req_attrs = NULL;
	session->find_ctx = find_ctx;
	find_ctx = NULL;
	rv = SKS_OK;

bail:
	TEE_Free(uuids_tbl);
	TEE_Free(req_attrs);
	TEE_Free(template);
	release_find_obj_context(find_ctx);

	return rv;
}

/*
 * Entry for command SKS_CMD_FIND_OBJECTS
 */
uint32_t entry_find_objects(uintptr_t tee_session, TEE_Param *ctrl,
			    TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct pkcs11_find_objects *ctx;
	uint32_t *out_handles;
	size_t out_count;
	size_t count;
	size_t idx;

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
		struct sks_object *obj;

		if (count >= out_count)
			break;

		*(out_handles + count) = *(ctx->handles + idx);
		ctx->next = idx + 1;

		if (idx < session->find_ctx->temp_start)
			continue;

		/* Newly pyublished handles: store in session list */
		obj = handle_lookup(&object_handle_db, *(ctx->handles + idx));
		if (!obj)
			TEE_Panic(0);

		LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	}

	/* Update output buffer accoriding the number of handles provided */
	out->memref.size = count * sizeof(uint32_t);

	return SKS_OK;
}

void release_session_find_obj_context(struct pkcs11_session *session)
{
	release_find_obj_context(session->find_ctx);
	session->find_ctx = NULL;
}

/*
 * Entry for command SKS_CMD_FIND_OBJECTS_FINAL
 */
uint32_t entry_find_objects_final(uintptr_t tee_session, TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;

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
