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

bool processing_is_tee_symm(uint32_t proc_id)
{
	switch (proc_id) {
	/* Authentication */
	case SKS_CKM_AES_CMAC_GENERAL:
	case SKS_CKM_AES_CMAC:
	case SKS_CKM_MD5_HMAC:
	case SKS_CKM_SHA_1_HMAC:
	case SKS_CKM_SHA224_HMAC:
	case SKS_CKM_SHA256_HMAC:
	case SKS_CKM_SHA384_HMAC:
	case SKS_CKM_SHA512_HMAC:
	case SKS_CKM_AES_XCBC_MAC:
	/* Cipherering */
	case SKS_CKM_AES_ECB:
	case SKS_CKM_AES_CBC:
	case SKS_CKM_AES_CBC_PAD:
	case SKS_CKM_AES_CTS:
	case SKS_CKM_AES_CTR:
	case SKS_CKM_AES_CCM:
	case SKS_CKM_AES_GCM:
		return true;
	default:
		return false;
	}
}

static uint32_t sks2tee_algorithm(uint32_t *tee_id,
			      struct sks_attribute_head *proc_params)
{
	static const uint32_t sks2tee_algo[][2] = {
		/* AES flavors */
		{ SKS_CKM_AES_ECB, TEE_ALG_AES_ECB_NOPAD },
		{ SKS_CKM_AES_CBC, TEE_ALG_AES_CBC_NOPAD },
		{ SKS_CKM_AES_CBC_PAD, TEE_ALG_AES_CBC_NOPAD }, // TODO
		{ SKS_CKM_AES_CTR, TEE_ALG_AES_CTR },
		{ SKS_CKM_AES_CTS, TEE_ALG_AES_CTS },
		{ SKS_CKM_AES_CCM, TEE_ALG_AES_CCM },
		{ SKS_CKM_AES_GCM, TEE_ALG_AES_GCM },
		{ SKS_CKM_AES_CMAC, TEE_ALG_AES_CMAC },
		{ SKS_CKM_AES_CMAC_GENERAL, TEE_ALG_AES_CMAC },
		{ SKS_CKM_AES_XCBC_MAC, TEE_ALG_AES_CBC_MAC_NOPAD },
		/* HMAC flavors */
		{ SKS_CKM_MD5_HMAC, TEE_ALG_HMAC_MD5 },
		{ SKS_CKM_SHA_1_HMAC, TEE_ALG_HMAC_SHA1 },
		{ SKS_CKM_SHA224_HMAC, TEE_ALG_HMAC_SHA224 },
		{ SKS_CKM_SHA256_HMAC, TEE_ALG_HMAC_SHA256 },
		{ SKS_CKM_SHA384_HMAC, TEE_ALG_HMAC_SHA384 },
		{ SKS_CKM_SHA512_HMAC, TEE_ALG_HMAC_SHA512 },
	};
	size_t end = sizeof(sks2tee_algo) / (2 * sizeof(uint32_t));
	size_t n = 0;

	for (n = 0; n < end; n++) {
		if (proc_params->id == sks2tee_algo[n][0]) {
			*tee_id = sks2tee_algo[n][1];
			break;
		}
	}

	if (n == end)
		return SKS_NOT_IMPLEMENTED;

	return SKS_OK;
}

static uint32_t sks2tee_key_type(uint32_t *tee_type, struct sks_object *obj)
{
	static const uint32_t sks2tee_key_type[][2] = {
		{ SKS_CKK_AES, TEE_TYPE_AES },
		{ SKS_CKK_GENERIC_SECRET, TEE_TYPE_GENERIC_SECRET },
		{ SKS_CKK_MD5_HMAC, TEE_TYPE_HMAC_MD5 },
		{ SKS_CKK_SHA_1_HMAC, TEE_TYPE_HMAC_SHA1 },
		{ SKS_CKK_SHA224_HMAC, TEE_TYPE_HMAC_SHA224 },
		{ SKS_CKK_SHA256_HMAC, TEE_TYPE_HMAC_SHA256 },
		{ SKS_CKK_SHA384_HMAC, TEE_TYPE_HMAC_SHA384 },
		{ SKS_CKK_SHA512_HMAC, TEE_TYPE_HMAC_SHA512 },
	};
	const size_t last = sizeof(sks2tee_key_type) / (2 * sizeof(uint32_t));
	size_t n = 0;
	uint32_t type = 0;

	type = get_type(obj->attributes);

	assert(get_class(obj->attributes) == SKS_CKO_SECRET_KEY);

	for (n = 0; n < last; n++) {
		if (sks2tee_key_type[n][0] == type) {
			*tee_type = sks2tee_key_type[n][1];
			return SKS_OK;
		}
	}

	return SKS_NOT_FOUND;
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

	if (sks2tee_algorithm(&algo, proc_params))
		return SKS_FAILED;

	/* Sign/Verify with AES or generic key relate to TEE MAC operation */
	switch (proc_params->id) {
	case SKS_CKM_AES_CMAC_GENERAL:
	case SKS_CKM_AES_CMAC:
	case SKS_CKM_MD5_HMAC:
	case SKS_CKM_SHA_1_HMAC:
	case SKS_CKM_SHA224_HMAC:
	case SKS_CKM_SHA256_HMAC:
	case SKS_CKM_SHA384_HMAC:
	case SKS_CKM_SHA512_HMAC:
	case SKS_CKM_AES_XCBC_MAC:
		mode = TEE_MODE_MAC;
		break;
	default:
		sks2tee_mode(&mode, function);
		break;
	}

	res = TEE_AllocateOperation(&session->processing->tee_op_handle,
				    algo, mode, size);
	if (res)
		EMSG("TEE_AllocateOp. failed %" PRIx32 " %" PRIx32 " %" PRIx32,
			algo, mode, size);

	return tee2sks_error(res);
}

static uint32_t load_tee_key(struct pkcs11_session *session,
				struct sks_object *obj)
{
	TEE_Attribute tee_attr;
	size_t object_size = 0;
	uint32_t key_type = 0;
	uint32_t rv = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_MemFill(&tee_attr, 0, sizeof(tee_attr));

	if (obj->key_handle != TEE_HANDLE_NULL) {
		/* Key was already loaded and fits current need */
		goto key_ready;
	}

	if (!sks2tee_load_attr(&tee_attr, TEE_ATTR_SECRET_VALUE,
			       obj, SKS_CKA_VALUE)) {
		EMSG("No secret found");
		return SKS_FAILED;
	}

	rv = sks2tee_key_type(&key_type, obj);
	if (rv)
		return rv;

	object_size = get_object_key_bit_size(obj);
	if (!object_size)
		return SKS_ERROR;

	res = TEE_AllocateTransientObject(key_type, object_size,
					  &obj->key_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, %" PRIx32, res);
		return tee2sks_error(res);
	}

	res = TEE_PopulateTransientObject(obj->key_handle, &tee_attr, 1);
	if (res) {
		DMSG("TEE_PopulateTransientObject failed, %" PRIx32, res);
		goto error;
	}

key_ready:
	res = TEE_SetOperationKey(session->processing->tee_op_handle,
				  obj->key_handle);
	if (res) {
		DMSG("TEE_SetOperationKey failed, %" PRIx32, res);
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
	uint32_t rv = SKS_ERROR;

	switch (proc_params->id) {
	case SKS_CKM_AES_CMAC_GENERAL:
	case SKS_CKM_AES_CMAC:
	case SKS_CKM_MD5_HMAC:
	case SKS_CKM_SHA_1_HMAC:
	case SKS_CKM_SHA224_HMAC:
	case SKS_CKM_SHA256_HMAC:
	case SKS_CKM_SHA384_HMAC:
	case SKS_CKM_SHA512_HMAC:
	case SKS_CKM_AES_XCBC_MAC:
		if (proc_params->size)
			return SKS_CKR_MECHANISM_PARAM_INVALID;

		TEE_MACInit(session->processing->tee_op_handle, NULL, 0);
		rv = SKS_OK;
		break;
	case SKS_CKM_AES_ECB:
		if (proc_params->size)
			return SKS_CKR_MECHANISM_PARAM_INVALID;

		TEE_CipherInit(session->processing->tee_op_handle, NULL, 0);
		rv = SKS_OK;
		break;
	case SKS_CKM_AES_CBC:
	case SKS_CKM_AES_CBC_PAD:
	case SKS_CKM_AES_CTS:
		if (proc_params->size != 16)
			return SKS_CKR_MECHANISM_PARAM_INVALID;

		TEE_CipherInit(session->processing->tee_op_handle,
			       proc_params->data, 16);
		rv = SKS_OK;
		break;
	case SKS_CKM_AES_CTR:
		rv = tee_init_ctr_operation(session->processing,
					    proc_params->data,
					    proc_params->size);
		break;
	case SKS_CKM_AES_CCM:
		rv = tee_init_ccm_operation(session->processing,
					    proc_params->data,
					    proc_params->size);
		break;
	case SKS_CKM_AES_GCM:
		rv = tee_init_gcm_operation(session->processing,
					    proc_params->data,
					    proc_params->size);
		break;
	default:
		TEE_Panic(proc_params->id);
		break;
	}

	return rv;
}

uint32_t init_symm_operation(struct pkcs11_session *session,
				enum processing_func function,
				struct sks_attribute_head *proc_params,
				struct sks_object *obj)
{
	uint32_t rv = 0;

	assert(processing_is_tee_symm(proc_params->id));

	rv = allocate_tee_operation(session, function, proc_params, obj);
	if (rv)
		return rv;

	rv = load_tee_key(session, obj);
	if (rv)
		return rv;

	return init_tee_operation(session, proc_params);
}

/*
 * step_sym_cipher - processing symmetric (and related) cipher operation step
 *
 * @session - current session
 * @function
 * @step - step ID in the processing (oneshot, update,final)
 * @in - input data reference #1
 * @io2 - input or output data reference #2, depending on function/step.
 */
uint32_t step_symm_operation(struct pkcs11_session *session,
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
	uint32_t out_size2 = out_size;
	void *in2_buf = io2 ? io2->memref.buffer : NULL;
	uint32_t in2_size = io2 ? io2->memref.size : 0;
	bool output_data = false;
	struct active_processing *proc = session->processing;

	switch (step) {
	case SKS_FUNC_STEP_ONESHOT:
	case SKS_FUNC_STEP_UPDATE:
	case SKS_FUNC_STEP_FINAL:
		break;
	default:
		return SKS_ERROR;
	}

	/*
	 * Feed active operation with with data
	 * (SKS_FUNC_STEP_UPDATE/_ONESHOT)
	 */
	switch (proc->mecha_type) {
	case SKS_CKM_AES_CMAC_GENERAL:
	case SKS_CKM_AES_CMAC:
	case SKS_CKM_MD5_HMAC:
	case SKS_CKM_SHA_1_HMAC:
	case SKS_CKM_SHA224_HMAC:
	case SKS_CKM_SHA256_HMAC:
	case SKS_CKM_SHA384_HMAC:
	case SKS_CKM_SHA512_HMAC:
	case SKS_CKM_AES_XCBC_MAC:
		if (step == SKS_FUNC_STEP_FINAL)
			break;

		if (!in) {
			DMSG("No input data");
			return SKS_BAD_PARAM;
		}

		switch (function) {
		case SKS_FUNCTION_SIGN:
		case SKS_FUNCTION_VERIFY:
			TEE_MACUpdate(proc->tee_op_handle, in_buf, in_size);
			rv = SKS_OK;
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case SKS_CKM_AES_ECB:
	case SKS_CKM_AES_CBC:
	case SKS_CKM_AES_CBC_PAD:
	case SKS_CKM_AES_CTS:
	case SKS_CKM_AES_CTR:
		if (step == SKS_FUNC_STEP_FINAL ||
		    step == SKS_FUNC_STEP_ONESHOT)
			break;

		switch (function) {
		case SKS_FUNCTION_ENCRYPT:
		case SKS_FUNCTION_DECRYPT:
			res = TEE_CipherUpdate(proc->tee_op_handle,
						in_buf, in_size,
						out_buf, &out_size);
			output_data = true;
			rv = tee2sks_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case SKS_CKM_AES_CCM:
	case SKS_CKM_AES_GCM:
		if (step == SKS_FUNC_STEP_FINAL)
			break;

		switch (function) {
		case SKS_FUNCTION_ENCRYPT:
			res = TEE_AEUpdate(proc->tee_op_handle,
					   in_buf, in_size, out_buf, &out_size);
			output_data = true;
			rv = tee2sks_error(res);

			if (step == SKS_FUNC_STEP_ONESHOT &&
			    (rv == SKS_OK || rv == SKS_SHORT_BUFFER)) {
				out_buf = (char *)out_buf + out_size;
				out_size2 -= out_size;
			}
			break;
		case SKS_FUNCTION_DECRYPT:
			rv = tee_ae_decrypt_update(proc, in_buf, in_size);
			out_size = 0;
			output_data = true;
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

	if (step == SKS_FUNC_STEP_UPDATE)
		goto bail;

	/*
	 * Finalize (SKS_FUNC_STEP_ONESHOT/_FINAL) operation
	 */
	switch (session->processing->mecha_type) {
	case SKS_CKM_AES_CMAC_GENERAL:
	case SKS_CKM_AES_CMAC:
	case SKS_CKM_MD5_HMAC:
	case SKS_CKM_SHA_1_HMAC:
	case SKS_CKM_SHA224_HMAC:
	case SKS_CKM_SHA256_HMAC:
	case SKS_CKM_SHA384_HMAC:
	case SKS_CKM_SHA512_HMAC:
	case SKS_CKM_AES_XCBC_MAC:
		switch (function) {
		case SKS_FUNCTION_SIGN:
			res = TEE_MACComputeFinal(proc->tee_op_handle,
						  NULL, 0, out_buf, &out_size);
			output_data = true;
			rv = tee2sks_error(res);
			break;
		case SKS_FUNCTION_VERIFY:
			res = TEE_MACCompareFinal(proc->tee_op_handle,
						  NULL, 0, in2_buf, in2_size);
			rv = tee2sks_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case SKS_CKM_AES_ECB:
	case SKS_CKM_AES_CBC:
	case SKS_CKM_AES_CBC_PAD:
	case SKS_CKM_AES_CTS:
	case SKS_CKM_AES_CTR:
		switch (function) {
		case SKS_FUNCTION_ENCRYPT:
		case SKS_FUNCTION_DECRYPT:
			res = TEE_CipherDoFinal(proc->tee_op_handle,
						in_buf, in_size,
						out_buf, &out_size);
			output_data = true;
			rv = tee2sks_error(res);
			break;
		default:
			TEE_Panic(function);
			break;
		}
		break;

	case SKS_CKM_AES_CCM:
	case SKS_CKM_AES_GCM:
		switch (function) {
		case SKS_FUNCTION_ENCRYPT:
			rv = tee_ae_encrypt_final(proc, out_buf, &out_size2);
			output_data = true;

			/*
			 * FIXME: on failure & ONESHOT, restore operation state
			 * before TEE_AEUpdate() was called
			 */
			if (step == SKS_FUNC_STEP_ONESHOT) {
				out_size += out_size2;
			} else {
				out_size = out_size2;
			}
			break;
		case SKS_FUNCTION_DECRYPT:
			rv = tee_ae_decrypt_final(proc, out_buf, &out_size);
			output_data = true;
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

	return rv;
}

uint32_t do_symm_derivation(struct pkcs11_session *session __unused,
			     struct sks_attribute_head *proc_params __unused,
			     struct sks_object *parent_key __unused,
			     struct sks_attrs_head **head __unused)
{
	EMSG("Symm key derivation not yet supported");
	return SKS_ERROR;
}
