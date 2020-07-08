// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"
#include "sks_helpers.h"

bool processing_is_tee_asymm(uint32_t proc_id)
{
	switch (proc_id) {
	/* RSA flavors */
	case SKS_CKM_RSA_PKCS:
	case SKS_CKM_RSA_PKCS_OAEP:
	case SKS_CKM_SHA1_RSA_PKCS:
	case SKS_CKM_SHA224_RSA_PKCS:
	case SKS_CKM_SHA256_RSA_PKCS:
	case SKS_CKM_SHA384_RSA_PKCS:
	case SKS_CKM_SHA512_RSA_PKCS:
	case SKS_CKM_SHA1_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS_PSS:
	case SKS_CKM_SHA256_RSA_PKCS_PSS:
	case SKS_CKM_SHA384_RSA_PKCS_PSS:
	case SKS_CKM_SHA512_RSA_PKCS_PSS:
	/* EC flavors */
	case SKS_CKM_ECDSA:
	case SKS_CKM_ECDSA_SHA1:
	case SKS_CKM_ECDSA_SHA224:
	case SKS_CKM_ECDSA_SHA256:
	case SKS_CKM_ECDSA_SHA384:
	case SKS_CKM_ECDSA_SHA512:
	case SKS_CKM_ECDH1_DERIVE:
	case SKS_CKM_ECDH1_COFACTOR_DERIVE:
		return true;
	default:
		return false;
	}
}

static uint32_t sks2tee_algorithm(uint32_t *tee_id,
				  enum processing_func function,
				  struct sks_attribute_head *proc_params,
				  struct sks_object *obj)
{
	static const uint32_t sks2tee_algo[][2] = {
		/* RSA flavors */
		{ SKS_CKM_RSA_PKCS, TEE_ALG_RSAES_PKCS1_V1_5
				/* TEE_ALG_RSASSA_PKCS1_V1_5 on signatures */ },
		{ SKS_CKM_RSA_PKCS_OAEP, 1 }, /* Need to look into params */
		{ SKS_CKM_SHA1_RSA_PKCS, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1 },
		{ SKS_CKM_SHA224_RSA_PKCS, TEE_ALG_RSASSA_PKCS1_V1_5_SHA224 },
		{ SKS_CKM_SHA256_RSA_PKCS, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 },
		{ SKS_CKM_SHA384_RSA_PKCS, TEE_ALG_RSASSA_PKCS1_V1_5_SHA384 },
		{ SKS_CKM_SHA512_RSA_PKCS, TEE_ALG_RSASSA_PKCS1_V1_5_SHA512 },
		{ SKS_CKM_SHA1_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 },
		{ SKS_CKM_SHA224_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 },
		{ SKS_CKM_SHA256_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 },
		{ SKS_CKM_SHA384_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 },
		{ SKS_CKM_SHA512_RSA_PKCS_PSS,
					TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 },
		/* EC flavors (Must find key size from the object) */
		{ SKS_CKM_ECDSA, 1 },
		{ SKS_CKM_ECDSA_SHA1, 1 },
		{ SKS_CKM_ECDSA_SHA224, 1 },
		{ SKS_CKM_ECDSA_SHA256, 1 },
		{ SKS_CKM_ECDSA_SHA384, 1 },
		{ SKS_CKM_ECDSA_SHA512, 1 },
		{ SKS_CKM_ECDH1_DERIVE, 1 },
		{ SKS_CKM_ECDH1_COFACTOR_DERIVE, 1 },
	};
	size_t end = sizeof(sks2tee_algo) / (2 * sizeof(uint32_t));
	size_t n = 0;
	uint32_t rv = 0;

	for (n = 0; n < end; n++) {
		if (proc_params->id == sks2tee_algo[n][0]) {
			*tee_id = sks2tee_algo[n][1];
			break;
		}
	}

	switch (proc_params->id) {
	case SKS_CKM_RSA_X_509:
	case SKS_CKM_RSA_9796:
	case SKS_CKM_RSA_PKCS_PSS:
		EMSG("%s not supported by GPD TEE, need an alternative...",
			sks2str_proc(proc_params->id));
		break;
	default:
		break;
	}

	if (n == end)
		return SKS_NOT_IMPLEMENTED;

	switch (proc_params->id) {
	case SKS_CKM_SHA1_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS_PSS:
	case SKS_CKM_SHA256_RSA_PKCS_PSS:
	case SKS_CKM_SHA384_RSA_PKCS_PSS:
	case SKS_CKM_SHA512_RSA_PKCS_PSS:
		rv = sks2tee_algo_rsa_pss(tee_id, proc_params);
		break;
	case SKS_CKM_RSA_PKCS_OAEP:
		rv = sks2tee_algo_rsa_oaep(tee_id, proc_params);
		break;
	case SKS_CKM_ECDH1_DERIVE:
		rv = sks2tee_algo_ecdh(tee_id, proc_params, obj);
		break;
	case SKS_CKM_ECDH1_COFACTOR_DERIVE:
		return SKS_NOT_IMPLEMENTED;
	case SKS_CKM_ECDSA:
	case SKS_CKM_ECDSA_SHA1:
	case SKS_CKM_ECDSA_SHA224:
	case SKS_CKM_ECDSA_SHA256:
	case SKS_CKM_ECDSA_SHA384:
	case SKS_CKM_ECDSA_SHA512:
		rv = sks2tee_algo_ecdsa(tee_id, proc_params, obj);
		break;
	default:
		rv = SKS_OK;
		break;
	}

	if (*tee_id == TEE_ALG_RSAES_PKCS1_V1_5 &&
	    (function == SKS_FUNCTION_SIGN || function == SKS_FUNCTION_VERIFY))
		*tee_id = TEE_ALG_RSASSA_PKCS1_V1_5;

	return rv;
}

static uint32_t sks2tee_key_type(uint32_t *tee_type, struct sks_object *obj,
				 enum processing_func function)
{
	uint32_t class = get_class(obj->attributes);
	uint32_t type = get_type(obj->attributes);

	switch (class) {
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
		break;
	default:
		TEE_Panic(class);
		break;
	}

	switch (type) {
	case SKS_CKK_EC:
		if (class == SKS_CKO_PRIVATE_KEY) {
			*tee_type = (function == SKS_FUNCTION_DERIVE) ?
					TEE_TYPE_ECDH_KEYPAIR :
					TEE_TYPE_ECDSA_KEYPAIR;
		} else {
			*tee_type = (function == SKS_FUNCTION_DERIVE) ?
					TEE_TYPE_ECDH_PUBLIC_KEY :
					TEE_TYPE_ECDSA_PUBLIC_KEY;
		}
		break;
	case SKS_CKK_RSA:
		if (class == SKS_CKO_PRIVATE_KEY) {
			*tee_type = TEE_TYPE_RSA_KEYPAIR;
		} else {
			*tee_type = TEE_TYPE_RSA_PUBLIC_KEY;
		}
		break;
	default:
		TEE_Panic(type);
		break;
	}

	return SKS_OK;
}

static uint32_t allocate_tee_operation(struct pkcs11_session *session,
					enum processing_func function,
					struct sks_attribute_head *proc_params,
					struct sks_object *obj)
{
	uint32_t size = (uint32_t)get_object_key_bit_size(obj);
	uint32_t algo = 0;
	uint32_t mode = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(session->processing->tee_op_handle == TEE_HANDLE_NULL);

	if (sks2tee_algorithm(&algo, function, proc_params, obj))
		return SKS_FAILED;

	sks2tee_mode(&mode, function);

	res = TEE_AllocateOperation(&session->processing->tee_op_handle,
				    algo, mode, size);
	switch (res) {
	case TEE_ERROR_NOT_SUPPORTED:
		return SKS_CKR_MECHANISM_INVALID;
	case TEE_SUCCESS:
		break;
	default:
		EMSG("TEE_AllocateOp. failed %" PRIx32 " %" PRIx32 " %" PRIx32,
			algo, mode, size);
	}

	return tee2sks_error(res);
}

static uint32_t load_tee_key(struct pkcs11_session *session,
				struct sks_object *obj,
				enum processing_func function)
{
	TEE_Attribute *tee_attrs = NULL;
	size_t tee_attrs_count = 0;
	size_t object_size = 0;
	uint32_t rv = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t __maybe_unused class = get_class(obj->attributes);
	uint32_t type = get_type(obj->attributes);

	assert(class == SKS_CKO_PUBLIC_KEY || class == SKS_CKO_PRIVATE_KEY);

	if (obj->key_handle != TEE_HANDLE_NULL) {
		switch (type) {
		case SKS_CKK_RSA:
			/* RSA loaded keys can be reused */
			assert((obj->key_type == TEE_TYPE_RSA_PUBLIC_KEY &&
				class == SKS_CKO_PUBLIC_KEY) ||
			       (obj->key_type == TEE_TYPE_RSA_KEYPAIR &&
				class == SKS_CKO_PRIVATE_KEY));
			goto key_ready;
		case SKS_CKK_EC:
			/* Reuse EC TEE key only if already DSA or DH */
			switch (obj->key_type) {
			case TEE_TYPE_ECDSA_PUBLIC_KEY:
			case TEE_TYPE_ECDSA_KEYPAIR:
				if (function != SKS_FUNCTION_DERIVE)
					goto key_ready;
				break;
			case TEE_TYPE_ECDH_PUBLIC_KEY:
			case TEE_TYPE_ECDH_KEYPAIR:
				if (function == SKS_FUNCTION_DERIVE)
					goto key_ready;
				break;
			default:
				assert(0);
				break;
			}
			break;
		default:
			assert(0);
			break;
		}

		TEE_FreeTransientObject(obj->key_handle);
		obj->key_handle = TEE_HANDLE_NULL;
	}

	rv = sks2tee_key_type(&obj->key_type, obj, function);
	if (rv)
		return rv;

	object_size = get_object_key_bit_size(obj);
	if (!object_size)
		return SKS_ERROR;

	switch (type) {
	case SKS_CKK_RSA:
		rv = load_tee_rsa_key_attrs(&tee_attrs, &tee_attrs_count, obj);
		break;
	case SKS_CKK_EC:
		rv = load_tee_ec_key_attrs(&tee_attrs, &tee_attrs_count, obj);
		break;
	default:
		break;
	}
	if (rv)
		return rv;

	res = TEE_AllocateTransientObject(obj->key_type, object_size,
					  &obj->key_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, 0x%" PRIx32, res);
		return tee2sks_error(res);
	}

	res = TEE_PopulateTransientObject(obj->key_handle,
					  tee_attrs, tee_attrs_count);

	TEE_Free(tee_attrs);

	if (res) {
		DMSG("TEE_PopulateTransientObject failed, 0x%" PRIx32, res);
		goto error;
	}

key_ready:
	res = TEE_SetOperationKey(session->processing->tee_op_handle,
				  obj->key_handle);
	if (res) {
		DMSG("TEE_SetOperationKey failed, 0x%" PRIx32, res);
		goto error;
	}

	return tee2sks_error(res);

error:
	TEE_FreeTransientObject(obj->key_handle);
	obj->key_handle = TEE_HANDLE_NULL;
	return tee2sks_error(res);
}

static uint32_t init_tee_operation(struct pkcs11_session *session,
				   struct sks_attribute_head *proc_params)
{
	uint32_t rv = SKS_OK;

	switch (proc_params->id) {
	case SKS_CKM_SHA1_RSA_PKCS_PSS:
	case SKS_CKM_SHA256_RSA_PKCS_PSS:
	case SKS_CKM_SHA384_RSA_PKCS_PSS:
	case SKS_CKM_SHA512_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS_PSS:
		rv = sks2tee_proc_params_rsa_pss(session->processing,
						 proc_params);
		break;
	default:
		break;
	}

	return rv;
}

uint32_t init_asymm_operation(struct pkcs11_session *session,
				enum processing_func function,
				struct sks_attribute_head *proc_params,
				struct sks_object *obj)
{
	uint32_t rv = 0;

	assert(processing_is_tee_asymm(proc_params->id));

	rv = allocate_tee_operation(session, function, proc_params, obj);
	if (rv)
		return rv;

	rv = load_tee_key(session, obj, function);
	if (rv)
		return rv;

	return init_tee_operation(session, proc_params);
}

/*
 * step_sym_step - step (update/oneshot/final) on a symmetric crypto operation
 *
 * @session - current session
 * @function -
 * @step - step ID in the processing (oneshot, update,final)
 * @in - input data reference #1
 * @io2 - input/output data reference #2 (direction depends on function)
 */
uint32_t step_asymm_operation(struct pkcs11_session *session,
			      enum processing_func function,
			      enum processing_step step,
			      TEE_Param *in, TEE_Param *io2)
{
	uint32_t rv = SKS_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	void *in_buf = in ? in->memref.buffer : NULL;
	size_t in_size = in ? in->memref.size : 0;
	void *out_buf = io2 ? io2->memref.buffer : NULL;
	uint32_t out_size = io2 ? io2->memref.size : 0;
	void *in2_buf = io2 ? io2->memref.buffer : NULL;
	uint32_t in2_size = io2 ? io2->memref.size : 0;
	TEE_Attribute *tee_attrs = NULL;
	size_t tee_attrs_count = 0;
	uint32_t data32 = 0;
	bool output_data = false;
	struct active_processing *proc = session->processing;
	TEE_OperationInfo opinfo;

	switch (step) {
	case SKS_FUNC_STEP_ONESHOT:
	case SKS_FUNC_STEP_UPDATE:
	case SKS_FUNC_STEP_FINAL:
		break;
	default:
		return SKS_ERROR;
	}

	/* TEE attribute(s) required by the operation */
	switch (proc->mecha_type) {
	case SKS_CKM_SHA1_RSA_PKCS_PSS:
	case SKS_CKM_SHA256_RSA_PKCS_PSS:
	case SKS_CKM_SHA384_RSA_PKCS_PSS:
	case SKS_CKM_SHA512_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS_PSS:
		tee_attrs = TEE_Malloc(sizeof(TEE_Attribute),
					TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!tee_attrs) {
			rv = SKS_MEMORY;
			goto bail;
		}

		data32 = *(uint32_t *)proc->extra_ctx;
		TEE_InitValueAttribute(&tee_attrs[tee_attrs_count],
					TEE_ATTR_RSA_PSS_SALT_LENGTH,
					data32, 0);
		tee_attrs_count++;
		break;
	default:
		break;
	}

	/* TEE attribute(s) required by the operation */
	switch (proc->mecha_type) {
	case SKS_CKM_ECDSA_SHA1:
	case SKS_CKM_ECDSA_SHA224:
	case SKS_CKM_ECDSA_SHA256:
	case SKS_CKM_ECDSA_SHA384:
	case SKS_CKM_ECDSA_SHA512:
		if (step == SKS_FUNC_STEP_FINAL)
			break;

		EMSG("TODO: compute hash for later authentication");
		rv = SKS_NOT_IMPLEMENTED;
		goto bail;
	default:
		/* Other mechanism do not expect multi stage operation */
		rv = SKS_ERROR;
		break;
	}

	if (step == SKS_FUNC_STEP_UPDATE)
		goto bail;

	/*
	 * Finalize
	 */

	/* These ECDSA need to use the computed hash as input data */
	switch (proc->mecha_type) {
	case SKS_CKM_ECDSA:
		/* Input size depends on the key size */
		if (!in_size) {
			rv = SKS_FAILED;
			goto bail;
		}
		TEE_GetOperationInfo(proc->tee_op_handle, &opinfo);
		switch (opinfo.algorithm) {
		case TEE_ALG_ECDSA_P192:
			if (in_size > 24)
				in_size = 24;
			break;
		case TEE_ALG_ECDSA_P224:
			if (in_size > 28)
				in_size = 28;
			break;
		case TEE_ALG_ECDSA_P256:
			if (in_size > 32)
				in_size = 32;
			break;
		case TEE_ALG_ECDSA_P384:
			if (in_size > 48)
				in_size = 48;
			break;
		case TEE_ALG_ECDSA_P521:
			if (in_size > 64)
				in_size = 64;
			break;
		default:
			rv = SKS_FAILED;
			goto bail;
		}
		/* Validate second input buffer size if verify */
		if (function == SKS_FUNCTION_VERIFY &&
				in2_size != 2 * in_size) {
			rv = SKS_CKR_SIGNATURE_LEN_RANGE;
			goto bail;
		}
		break;
	case SKS_CKM_ECDSA_SHA1:
		in_buf = proc->extra_ctx;
		in_size = 192;
		break;
	case SKS_CKM_ECDSA_SHA224:
		in_buf = proc->extra_ctx;
		in_size = 224;
		break;
	case SKS_CKM_ECDSA_SHA256:
		in_buf = proc->extra_ctx;
		in_size = 256;
		break;
	case SKS_CKM_ECDSA_SHA384:
		in_buf = proc->extra_ctx;
		in_size = 384;
		break;
	case SKS_CKM_ECDSA_SHA512:
		in_buf = proc->extra_ctx;
		in_size = 512;
		break;
	default:
		if (step != SKS_FUNC_STEP_ONESHOT) {
			rv = SKS_ERROR;
			goto bail;
		}
		break;
	}

	switch (proc->mecha_type) {
	case SKS_CKM_ECDSA:
	case SKS_CKM_ECDSA_SHA1:
	case SKS_CKM_ECDSA_SHA224:
	case SKS_CKM_ECDSA_SHA256:
	case SKS_CKM_ECDSA_SHA384:
	case SKS_CKM_ECDSA_SHA512:
	case SKS_CKM_RSA_PKCS:
	case SKS_CKM_RSA_9796:
	case SKS_CKM_RSA_X_509:
	case SKS_CKM_SHA1_RSA_PKCS:
	case SKS_CKM_RSA_PKCS_OAEP:
	case SKS_CKM_RSA_PKCS_PSS:
	case SKS_CKM_SHA1_RSA_PKCS_PSS:
	case SKS_CKM_SHA256_RSA_PKCS_PSS:
	case SKS_CKM_SHA384_RSA_PKCS_PSS:
	case SKS_CKM_SHA512_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS:
	case SKS_CKM_SHA256_RSA_PKCS:
	case SKS_CKM_SHA384_RSA_PKCS:
	case SKS_CKM_SHA512_RSA_PKCS:
		switch (function) {
		case SKS_FUNCTION_ENCRYPT:
			// TODO: TEE_ALG_RSAES_PKCS1_OAEP_MGF1_xxx takes an
			// optional argument TEE_ATTR_RSA_OAEP_LABEL.
			res = TEE_AsymmetricEncrypt(proc->tee_op_handle,
						    tee_attrs, tee_attrs_count,
						    in_buf, in_size,
						    out_buf, &out_size);
			output_data = true;
			rv = tee2sks_error(res);
			break;

		case SKS_FUNCTION_DECRYPT:
			res = TEE_AsymmetricDecrypt(proc->tee_op_handle,
						    tee_attrs, tee_attrs_count,
						    in_buf, in_size,
						    out_buf, &out_size);
			output_data = true;
			rv = tee2sks_error(res);
			break;

		case SKS_FUNCTION_SIGN:
			res = TEE_AsymmetricSignDigest(proc->tee_op_handle,
							tee_attrs,
							tee_attrs_count,
							in_buf, in_size,
							out_buf, &out_size);
			output_data = true;
			rv = tee2sks_error(res);
			break;

		case SKS_FUNCTION_VERIFY:
			res = TEE_AsymmetricVerifyDigest(proc->tee_op_handle,
							 tee_attrs,
							 tee_attrs_count,
							 in_buf, in_size,
							 in2_buf, in2_size);
			rv = tee2sks_error(res);
			break;

		default:
			TEE_Panic(function);
			break;
		}
		break;
	default:
		TEE_Panic(proc->mecha_type);
		break;
	}
bail:
	if (output_data && (rv == SKS_OK || rv == SKS_SHORT_BUFFER)) {
		if (io2)
			io2->memref.size = out_size;
		else
			rv = SKS_ERROR;
	}

	TEE_Free(tee_attrs);

	return rv;
}

uint32_t do_asymm_derivation(struct pkcs11_session *session,
			     struct sks_attribute_head *proc_params,
			     struct sks_attrs_head **head)
{
	uint32_t rv = SKS_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Attribute tee_attrs[2];
	size_t tee_attrs_count = 0;
	TEE_ObjectHandle out_handle = TEE_HANDLE_NULL;
	void *a_ptr = NULL;
	size_t a_size = 0;
	uint32_t key_byte_size = 0;

	TEE_MemFill(tee_attrs, 0, sizeof(tee_attrs));

	rv = get_u32_attribute(*head, SKS_CKA_VALUE_LEN, &key_byte_size);
	if (rv)
		return rv;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					  key_byte_size * 8, &out_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, 0x%" PRIx32, res);
		return tee2sks_error(res);
	}

	switch (proc_params->id) {
	case SKS_CKM_ECDH1_DERIVE:
	case SKS_CKM_ECDH1_COFACTOR_DERIVE:
		rv = sks2tee_ecdh_param_pub(proc_params, &a_ptr, &a_size);
		if (rv)
			goto bail;

		// TODO: check size is the expected one (active proc key)
		TEE_InitRefAttribute(&tee_attrs[tee_attrs_count],
						TEE_ATTR_ECC_PUBLIC_VALUE_X,
						a_ptr, a_size / 2);
		tee_attrs_count++;

		TEE_InitRefAttribute(&tee_attrs[tee_attrs_count],
						TEE_ATTR_ECC_PUBLIC_VALUE_Y,
						(char *)a_ptr + a_size / 2,
						a_size / 2);
		tee_attrs_count++;
		break;
	case SKS_CKM_DH_PKCS_DERIVE:
		TEE_InitRefAttribute(&tee_attrs[tee_attrs_count],
						TEE_ATTR_DH_PUBLIC_VALUE,
						proc_params->data,
						proc_params->size);
		tee_attrs_count++;
		break;
	default:
		TEE_Panic(proc_params->id);
		break;
	}

	TEE_DeriveKey(session->processing->tee_op_handle,
			&tee_attrs[0], tee_attrs_count, out_handle);

	rv = alloc_get_tee_attribute_data(out_handle, TEE_ATTR_SECRET_VALUE,
					  &a_ptr, &a_size);
	if (rv)
		goto bail;

	if (a_size < key_byte_size) {
		rv = SKS_CKR_KEY_SIZE_RANGE;
	} else {
		rv = add_attribute(head, SKS_CKA_VALUE, a_ptr, key_byte_size);
	}

	TEE_Free(a_ptr);
bail:
	release_active_processing(session);
	TEE_FreeTransientObject(out_handle);
	return rv;
}
