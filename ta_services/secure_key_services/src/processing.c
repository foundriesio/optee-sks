// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <assert.h>
#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_token.h"
#include "pkcs11_attributes.h"
#include "processing.h"
#include "serializer.h"
#include "sks_helpers.h"

static uint32_t get_ready_session(struct pkcs11_session **sess,
				  uint32_t session_handle,
				  uintptr_t tee_session)
{
	struct pkcs11_session *session;

	session = sks_handle2session(session_handle, tee_session);
	if (!session)
		return SKS_CKR_SESSION_HANDLE_INVALID;

	if (session_is_active(session))
		return SKS_CKR_OPERATION_ACTIVE;

	*sess = session;

	return SKS_OK;
}

static bool func_matches_state(enum processing_func function,
				enum pkcs11_proc_state state)
{
	switch (function) {
	case SKS_FUNCTION_ENCRYPT:
		return (state == PKCS11_SESSION_ENCRYPTING ||
			state == PKCS11_SESSION_DIGESTING_ENCRYPTING ||
			state == PKCS11_SESSION_SIGNING_ENCRYPTING);
	case SKS_FUNCTION_DECRYPT:
		return (state == PKCS11_SESSION_DECRYPTING ||
			state == PKCS11_SESSION_DECRYPTING_DIGESTING ||
			state == PKCS11_SESSION_DECRYPTING_VERIFYING);
	case SKS_FUNCTION_DIGEST:
		return (state == PKCS11_SESSION_DIGESTING ||
			state == PKCS11_SESSION_DIGESTING_ENCRYPTING);
	case SKS_FUNCTION_SIGN:
		return (state == PKCS11_SESSION_SIGNING ||
			state == PKCS11_SESSION_SIGNING_ENCRYPTING);
	case SKS_FUNCTION_VERIFY:
		return (state == PKCS11_SESSION_VERIFYING ||
			state == PKCS11_SESSION_DECRYPTING_VERIFYING);
	case SKS_FUNCTION_SIGN_RECOVER:
		return state == PKCS11_SESSION_SIGNING_RECOVER;
	case SKS_FUNCTION_VERIFY_RECOVER:
		return state == PKCS11_SESSION_SIGNING_RECOVER;
	default:
		TEE_Panic(function);
		return false;
	}
}

static uint32_t get_active_session(struct pkcs11_session **sess,
				  uint32_t session_handle,
				  uintptr_t tee_session,
				  enum processing_func function)
{
	struct pkcs11_session *session;
	uint32_t rv = SKS_CKR_OPERATION_NOT_INITIALIZED;

	session = sks_handle2session(session_handle, tee_session);
	if (!session)
		return SKS_CKR_SESSION_HANDLE_INVALID;

	if (session->processing &&
	    func_matches_state(function, session->processing->state)) {
		*sess = session;
		rv = SKS_OK;
	}

	return rv;
}

void release_active_processing(struct pkcs11_session *session)
{
	if (!session->processing)
		return;

	switch (session->processing->mecha_type) {
	case SKS_CKM_AES_CTR:
		tee_release_ctr_operation(session->processing);
		break;
	case SKS_CKM_AES_GCM:
		tee_release_gcm_operation(session->processing);
		break;
	case SKS_CKM_AES_CCM:
		tee_release_ccm_operation(session->processing);
		break;
	case SKS_CKM_SHA1_RSA_PKCS_PSS:
	case SKS_CKM_SHA256_RSA_PKCS_PSS:
	case SKS_CKM_SHA384_RSA_PKCS_PSS:
	case SKS_CKM_SHA512_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS_PSS:
		tee_release_rsa_pss_operation(session->processing);
		break;
	default:
		break;
	}

	if (session->processing->tee_op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session->processing->tee_op_handle);
		session->processing->tee_op_handle = TEE_HANDLE_NULL;
	}

	TEE_Free(session->processing);
	session->processing = NULL;
}

uint32_t entry_import_object(uintptr_t tee_session,
			     TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_attrs_head *head = NULL;
	struct sks_object_head *template = NULL;
	size_t template_size;
	uint32_t obj_handle;

	/*
	 * Collect the arguments of the request
	 */

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(uint32_t)) {
		out->memref.size = sizeof(uint32_t);
		return SKS_SHORT_BUFFER;
	}

	if ((uintptr_t)out->memref.buffer & 0x3UL)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = get_ready_session(&session, session_handle, tee_session);
	if (rv)
		return rv;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	template_size = sizeof(*template) + template->attrs_size;

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temorary template once done.
	 */
	rv = create_attributes_from_template(&head, template, template_size,
					     NULL, SKS_FUNCTION_IMPORT);
	TEE_Free(template);
	template = NULL;
	if (rv)
		goto bail;

	/*
	 * Check target object attributes match target processing
	 * Check target object attributes match token state
	 */
	rv = check_created_attrs_against_processing(SKS_PROCESSING_IMPORT,
						    head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	/*
	 * TODO: test object (will check all expected attributes are in place
	 */

	/*
	 * At this stage the object is almost created: all its attributes are
	 * referenced in @head, including the key value and are assume
	 * reliable. Now need to register it and get a handle for it.
	 */
	rv = create_object(session, head, &obj_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct sks_object instance)
	 * owns the serialised buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

bail:
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}

size_t get_object_key_bit_size(struct sks_object *obj)
{
	void *a_ptr;
	size_t a_size;
	struct sks_attrs_head *attrs = obj->attributes;

	switch (get_type(attrs)) {
	case SKS_CKK_AES:
	case SKS_CKK_GENERIC_SECRET:
	case SKS_CKK_MD5_HMAC:
	case SKS_CKK_SHA_1_HMAC:
	case SKS_CKK_SHA224_HMAC:
	case SKS_CKK_SHA256_HMAC:
	case SKS_CKK_SHA384_HMAC:
	case SKS_CKK_SHA512_HMAC:
		if (get_attribute_ptr(attrs, SKS_CKA_VALUE, NULL, &a_size))
			return 0;

		return a_size * 8;

	case SKS_CKK_RSA:
		if (get_attribute_ptr(attrs, SKS_CKA_MODULUS, NULL, &a_size))
			return 0;

		return a_size * 8;

	case SKS_CKK_EC:
		if (get_attribute_ptr(attrs, SKS_CKA_EC_PARAMS,
					&a_ptr, &a_size))
			return 0;

		return ec_params2tee_keysize(a_ptr, a_size);

	default:
		TEE_Panic(0);
		return 0;
	}
}

static uint32_t generate_random_key_value(struct sks_attrs_head **head)
{
	uint32_t rv;
	void *data;
	size_t data_size;
	uint32_t value_len;
	void *value;

	if (!*head)
		return SKS_CKR_TEMPLATE_INCONSISTENT;

	rv = get_attribute_ptr(*head, SKS_CKA_VALUE_LEN, &data, &data_size);
	if (rv || data_size != sizeof(uint32_t)) {
		DMSG("%s", rv ? "No attribute value_len found" :
			"Invalid size for attribute VALUE_LEN");
		return SKS_CKR_ATTRIBUTE_VALUE_INVALID;
	}
	TEE_MemMove(&value_len, data, data_size);

	if (get_type(*head) == SKS_CKK_GENERIC_SECRET)
		value_len = (value_len + 7) / 8;

	value = TEE_Malloc(value_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!value)
		return SKS_MEMORY;

	TEE_GenerateRandom(value, value_len);

	rv = add_attribute(head, SKS_CKA_VALUE, value, value_len);

	TEE_Free(value);

	return rv;
}

uint32_t entry_generate_secret(uintptr_t tee_session,
			       TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_attribute_head *proc_params = NULL;
	struct sks_attrs_head *head = NULL;
	struct sks_object_head *template = NULL;
	size_t template_size;
	uint32_t obj_handle;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(uint32_t)) {
		out->memref.size = sizeof(uint32_t);
		return SKS_SHORT_BUFFER;
	}

	if ((uintptr_t)out->memref.buffer & 0x3UL)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = get_ready_session(&session, session_handle, tee_session);
	if (rv)
		return rv;

	rv = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rv)
		goto bail;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	template_size = sizeof(*template) + template->attrs_size;

	rv = check_mechanism_against_processing(session, proc_params->id,
						SKS_FUNCTION_GENERATE,
						SKS_FUNC_STEP_INIT);
	if (rv)
		goto bail;

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temorary template once done.
	 */
	rv = create_attributes_from_template(&head, template, template_size,
					     NULL, SKS_FUNCTION_GENERATE);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	/*
	 * Check created object against processing and token state.
	 */
	rv = check_created_attrs_against_processing(proc_params->id, head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	/*
	 * Execute target processing and add value as attribute SKS_CKA_VALUE.
	 * Symm key generation: depens on target processing to be used.
	 */
	switch (proc_params->id) {
	case SKS_CKM_GENERIC_SECRET_KEY_GEN:
	case SKS_CKM_AES_KEY_GEN:
		/* Generate random of size specified by attribute VALUE_LEN */
		rv = generate_random_key_value(&head);
		if (rv)
			goto bail;
		break;

	default:
		rv = SKS_CKR_MECHANISM_INVALID;
		goto bail;
	}

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rv = create_object(session, head, &obj_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct sks_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

bail:
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}

uint32_t alloc_get_tee_attribute_data(TEE_ObjectHandle tee_obj,
					     uint32_t attribute,
					     void **data, size_t *size)
{
	TEE_Result res;
	void *ptr;
	size_t sz = 0;

	res = TEE_GetObjectBufferAttribute(tee_obj, attribute, NULL, &sz);
	if (res != TEE_ERROR_SHORT_BUFFER)
		return SKS_FAILED;

	ptr = TEE_Malloc(sz, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!ptr)
		return SKS_MEMORY;

	res = TEE_GetObjectBufferAttribute(tee_obj, attribute, ptr, &sz);
	if (res) {
		TEE_Free(ptr);
	} else {
		*data = ptr;
		*size = sz;
	}

	return tee2sks_error(res);
}

uint32_t tee2sks_add_attribute(struct sks_attrs_head **head, uint32_t sks_id,
				TEE_ObjectHandle tee_obj, uint32_t tee_id)
{
	uint32_t rv;
	void *a_ptr = NULL;
	size_t a_size = 0;

	rv = alloc_get_tee_attribute_data(tee_obj, tee_id, &a_ptr, &a_size);
	if (rv)
		goto bail;

	rv = add_attribute(head, sks_id, a_ptr, a_size);

	TEE_Free(a_ptr);

bail:
	if (rv)
		EMSG("Failed TEE attribute 0x%" PRIx32 "for %s (0x%" PRIx32 ")",
				tee_id, sks2str_attr(sks_id), sks_id);
	return rv;
}

uint32_t entry_generate_key_pair(uintptr_t teesess,
				 TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_attribute_head *proc_params = NULL;
	struct sks_attrs_head *pub_head = NULL;
	struct sks_attrs_head *priv_head = NULL;
	struct sks_object_head *template = NULL;
	size_t template_size;
	uint32_t pubkey_handle;
	uint32_t privkey_handle;
	uint32_t *hdl_ptr;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < 2 * sizeof(uint32_t))
		return SKS_SHORT_BUFFER;

	// FIXME: cleaner way to test alignment of out buffer
	if ((uintptr_t)out->memref.buffer & 0x3UL)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = get_ready_session(&session, session_handle, teesess);
	if (rv)
		return rv;

	/* Get mechanism parameters */
	rv = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rv)
		goto bail;

	rv = check_mechanism_against_processing(session, proc_params->id,
						SKS_FUNCTION_GENERATE_PAIR,
						SKS_FUNC_STEP_INIT);
	if (rv)
		goto bail;

	/* Get and check public key attributes */
	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	template_size = sizeof(*template) + template->attrs_size;

	rv = create_attributes_from_template(&pub_head, template, template_size,
					     NULL, SKS_FUNCTION_GENERATE_PAIR);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	rv = serialargs_alloc_get_attributes(&ctrlargs, &template);
	if (rv)
		goto bail;

	template_size = sizeof(*template) + template->attrs_size;

	rv = create_attributes_from_template(&priv_head, template, template_size,
					     NULL, SKS_FUNCTION_GENERATE_PAIR);
	if (rv)
		goto bail;

	TEE_Free(template);
	template = NULL;

	/* Check created object against processing and token state */
	rv = check_created_attrs_against_processing(proc_params->id, pub_head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_processing(proc_params->id, priv_head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, pub_head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, priv_head);
	if (rv)
		goto bail;

	/* Generate key pair */
	switch (proc_params->id) {
	case SKS_CKM_EC_KEY_PAIR_GEN:
		rv = generate_ec_keys(proc_params, &pub_head, &priv_head);
		break;

	case SKS_CKM_RSA_PKCS_KEY_PAIR_GEN:
		rv = generate_rsa_keys(proc_params, &pub_head, &priv_head);
		break;
	default:
		rv = SKS_CKR_MECHANISM_INVALID;
		break;
	}
	if (rv)
		goto bail;

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rv = create_object(session, pub_head, &pubkey_handle);
	if (rv)
		goto bail;

	rv = create_object(session, priv_head, &privkey_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct sks_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	pub_head = NULL;
	priv_head = NULL;
	hdl_ptr = (uint32_t *)out->memref.buffer;

	TEE_MemMove(hdl_ptr, &pubkey_handle, sizeof(uint32_t));
	TEE_MemMove(hdl_ptr + 1, &privkey_handle, sizeof(uint32_t));
	out->memref.size = 2 * sizeof(uint32_t);

bail:
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(pub_head);
	TEE_Free(priv_head);

	return rv;
}

/*
 * entry_processing_init - Generic entry for initializing a processing
 *
 * @ctrl = [session-handle]
 * @in = input data or none
 * @out = output data or none
 * @function - encrypt, decrypt, sign, verify, disgest, ...
 *
 * The generic part come that all the commands uses the same
 * input/output invocation parameters format (ctrl/in/out).
 */
uint32_t entry_processing_init(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out,
				enum processing_func function)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session = NULL;
	struct sks_attribute_head *proc_params = NULL;
	uint32_t key_handle;
	struct sks_object *obj;

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = get_ready_session(&session, session_handle, tee_session);
	if (rv)
		return rv;

	rv = serialargs_get(&ctrlargs, &key_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	obj = sks_handle2object(key_handle, session);
	if (!obj)
		return SKS_CKR_KEY_HANDLE_INVALID;

	rv = set_processing_state(session, function, obj, NULL);
	if (rv)
		return rv;

	rv = serialargs_alloc_get_one_attribute(&ctrlargs, &proc_params);
	if (rv)
		goto bail;

	rv = check_mechanism_against_processing(session, proc_params->id,
						function, SKS_FUNC_STEP_INIT);
	if (rv)
		goto bail;

	rv = check_parent_attrs_against_processing(proc_params->id, function,
						   obj->attributes);
	if (rv)
		goto bail;

	rv = check_access_attrs_against_token(session, obj->attributes);
	if (rv)
		goto bail;

	rv = SKS_CKR_MECHANISM_INVALID;
	if (processing_is_tee_symm(proc_params->id)) {
		rv = init_symm_operation(session, function, proc_params, obj);
	}
	if (processing_is_tee_asymm(proc_params->id)) {
		rv = init_asymm_operation(session, function, proc_params, obj);
	}
	if (rv == SKS_OK) {
		session->processing->mecha_type = proc_params->id;
	}

bail:
	if (rv && session)
		release_active_processing(session);

	TEE_Free(proc_params);

	return rv;
}

/*
 * entry_processing_step - Generic entry on active processing
 *
 * @ctrl = [session-handle]
 * @in = input data or none
 * @out = output data or none
 * @function - encrypt, decrypt, sign, verify, disgest, ...
 * @step - update, oneshot, final
 *
 * The generic part come that all the commands uses the same
 * input/output invocation parameters format (ctrl/in/out).
 */
uint32_t entry_processing_step(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out,
				enum processing_func function,
				enum processing_step step)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	uint32_t mecha_type;

	if (!ctrl)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = get_active_session(&session, session_handle, tee_session,
				function);
	if (rv)
		return rv;

	// TODO: check user authen and object activiation dates
	mecha_type = session->processing->mecha_type;
	rv = check_mechanism_against_processing(session, mecha_type,
						function, step);
	if (rv)
		goto bail;

	rv = SKS_CKR_MECHANISM_INVALID;
	if (processing_is_tee_symm(mecha_type)) {
		rv = step_symm_operation(session, function, step, in, out);
	}
	if (processing_is_tee_asymm(mecha_type)) {
		rv = step_asymm_operation(session, function, step, in, out);
	}
	if (rv == SKS_OK)
		session->processing->updated = true;

bail:
	switch (step) {
	case SKS_FUNC_STEP_UPDATE:
		if (rv != SKS_OK && rv != SKS_SHORT_BUFFER)
			release_active_processing(session);
		break;
	default:
		/* ONESHOT and FINAL terminates procceesing on success */
		if (rv != SKS_SHORT_BUFFER)
			release_active_processing(session);
		break;
	}

	return rv;
}

/*
 * entry_verify_oneshot - Generic entry on active processing
 *
 * @ctrl = [session-handle]
 * @in = input data or none
 * @out = output data or none
 * @function - encrypt, decrypt, sign, verify, disgest, ...
 * @step - update, oneshot, final
 *
 * The generic part come that all the commands uses the same
 * input/output invocation parameters format (ctrl/in/out).
 */
uint32_t entry_verify_oneshot(uintptr_t tee_session, TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *in2,
				  enum processing_func function,
				  enum processing_step step)

{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	uint32_t mecha_type;

	assert(function == SKS_FUNCTION_VERIFY);

	if (!ctrl)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rv = serialargs_get(&ctrlargs, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = get_active_session(&session, session_handle, tee_session,
				function);
	if (rv)
		return rv;

	// TODO: check user authen and object activiation dates
	mecha_type = session->processing->mecha_type;
	rv = check_mechanism_against_processing(session, mecha_type,
						function, step);
	if (rv)
		goto bail;

	rv = SKS_CKR_MECHANISM_INVALID;
	if (processing_is_tee_symm(mecha_type)) {
		rv = step_symm_operation(session, function, step, in, in2);
	}
	if (processing_is_tee_asymm(mecha_type)) {
		rv = step_asymm_operation(session, function, step, in, in2);
	}
bail:
	if (rv != SKS_SHORT_BUFFER)
		release_active_processing(session);

	return rv;
}
