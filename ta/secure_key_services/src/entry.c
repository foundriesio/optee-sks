// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <compiler.h>
#include <sks_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "handle.h"
#include "object.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "sks_helpers.h"

/* Client session context: currently only use the alloced address */
struct tee_session {
	int foo;
};


TEE_Result TA_CreateEntryPoint(void)
{
	if (pkcs11_init())
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	pkcs11_deinit();
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **tee_session)
{
	uintptr_t client = register_client();

	if (!client)
		return TEE_ERROR_OUT_OF_MEMORY;

	*tee_session = (void *)client;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *tee_session)
{
	unregister_client((uintptr_t)tee_session);
}

static uint32_t entry_ping(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t *ver = NULL;

	if (ctrl || in)
		return SKS_BAD_PARAM;

	if (!out)
		return SKS_OK;

	if (out->memref.size < 2 * sizeof(uint32_t))
		return SKS_SHORT_BUFFER;

	if ((uintptr_t)out->memref.buffer & 0x03UL)
		return SKS_BAD_PARAM;

	ver = (uint32_t *)out->memref.buffer;
	*ver = SKS_VERSION_ID0;
	*(ver + 1) = SKS_VERSION_ID1;

	return SKS_OK;
}

/*
 * Entry point for SKS TA commands
 *
 * ABI: param#0 is the control buffer with serialazed arguments.
 *	param#1 is an input/output data buffer
 *	param#2 is an input/output data buffer (also used to return handles)
 *	param#3 is not used
 *
 * Param#0 ctrl, if defined is an in/out buffer, is used to send back to
 * the client a Cryptoki status ID that superseeds the TEE result code which
 * will be force to TEE_SUCCESS. Note that some Cryptoki error status are
 * sent straight through TEE result code. See sks2tee_noerr().
 */
TEE_Result TA_InvokeCommandEntryPoint(void *tee_session, uint32_t cmd,
				      uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Param *ctrl = NULL;
	TEE_Param *p1_in = NULL;
	TEE_Param __maybe_unused *p1_out = NULL;
	TEE_Param *p2_in = NULL;
	TEE_Param *p2_out = NULL;
	uintptr_t teesess = (uintptr_t)tee_session;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t rc = 0;

	/* param#0: input buffer with request serialazed arguments */
	switch (TEE_PARAM_TYPE_GET(ptypes, 0)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		ctrl = &params[0];
		break;
	default:
		goto bad_types;
	}

	/* param#1: input data buffer */
	switch (TEE_PARAM_TYPE_GET(ptypes, 1)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		p1_in = &params[1];
		break;
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		p1_out = &params[1];
		break;
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		p1_in = &params[1];
		p1_out = &params[1];
		break;
	default:
		goto bad_types;
	}

	/* param#2: input or output data buffer */
	switch (TEE_PARAM_TYPE_GET(ptypes, 2)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		p2_in = &params[2];
		break;
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		p2_out = &params[2];
		break;
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		p2_in = &params[2];
		p2_out = &params[2];
		break;
	default:
		goto bad_types;
	}

	/* param#3: unused */
	switch (TEE_PARAM_TYPE_GET(ptypes, 3)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	default:
		goto bad_types;
	}

	DMSG("%s ctrl %" PRIu32 "@%p, %s %" PRIu32 "@%p, %s %" PRIu32 "@%p",
		sks2str_skscmd(cmd),
		ctrl ? ctrl->memref.size : 0, ctrl ? ctrl->memref.buffer : 0,
		p1_out ? "out" : (p1_in ? "in" : "---"),
		p1_out ? p1_out->memref.size : (p1_in ? p1_in->memref.size : 0),
		p1_out ? p1_out->memref.buffer :
			(p1_in ? p1_in->memref.buffer : NULL),
		p2_out ? "out" : (p2_in ? "in" : "---"),
		p2_out ? p2_out->memref.size : (p2_in ? p2_in->memref.size : 0),
		p2_out ? p2_out->memref.buffer :
			(p2_in ? p2_in->memref.buffer : NULL));

	switch (cmd) {
	case SKS_CMD_PING:
		rc = entry_ping(ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_CK_SLOT_LIST:
		rc = entry_ck_slot_list(ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_CK_SLOT_INFO:
		rc = entry_ck_slot_info(ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_CK_TOKEN_INFO:
		rc = entry_ck_token_info(ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_CK_INIT_TOKEN:
		rc = entry_ck_token_initialize(ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_CK_MECHANISM_IDS:
		rc = entry_ck_token_mecha_ids(ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_CK_MECHANISM_INFO:
		rc = entry_ck_token_mecha_info(ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_CK_OPEN_RO_SESSION:
		rc = entry_ck_token_ro_session(teesess, ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_CK_OPEN_RW_SESSION:
		rc = entry_ck_token_rw_session(teesess, ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_CK_CLOSE_SESSION:
		rc = entry_ck_token_close_session(teesess, ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_CK_CLOSE_ALL_SESSIONS:
		rc = entry_ck_token_close_all(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_IMPORT_OBJECT:
		rc = entry_import_object(teesess, ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_DESTROY_OBJECT:
		rc = entry_destroy_object(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_ENCRYPT_INIT:
		rc = entry_processing_init(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_ENCRYPT);
		break;
	case SKS_CMD_DECRYPT_INIT:
		rc = entry_processing_init(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_DECRYPT);
		break;
	case SKS_CMD_ENCRYPT_UPDATE:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_ENCRYPT,
					   SKS_FUNC_STEP_UPDATE);
		break;
	case SKS_CMD_DECRYPT_UPDATE:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_DECRYPT,
					   SKS_FUNC_STEP_UPDATE);
		break;
	case SKS_CMD_ENCRYPT_ONESHOT:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_ENCRYPT,
					   SKS_FUNC_STEP_ONESHOT);
		break;
	case SKS_CMD_DECRYPT_ONESHOT:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_DECRYPT,
					   SKS_FUNC_STEP_ONESHOT);
		break;
	case SKS_CMD_ENCRYPT_FINAL:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_ENCRYPT,
					   SKS_FUNC_STEP_FINAL);
		break;
	case SKS_CMD_DECRYPT_FINAL:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_DECRYPT,
					   SKS_FUNC_STEP_FINAL);
		break;

	case SKS_CMD_GENERATE_SYMM_KEY:
		rc = entry_generate_secret(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_SIGN_INIT:
		rc = entry_processing_init(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_SIGN);
		break;
	case SKS_CMD_VERIFY_INIT:
		rc = entry_processing_init(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_VERIFY);
		break;
	case SKS_CMD_SIGN_ONESHOT:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_SIGN,
					   SKS_FUNC_STEP_ONESHOT);
		break;
	case SKS_CMD_VERIFY_ONESHOT:
		rc = entry_verify_oneshot(teesess, ctrl, p1_in, p2_in,
					   SKS_FUNCTION_VERIFY,
					   SKS_FUNC_STEP_ONESHOT);
		break;
	case SKS_CMD_SIGN_UPDATE:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_SIGN,
					   SKS_FUNC_STEP_UPDATE);
		break;
	case SKS_CMD_VERIFY_UPDATE:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_VERIFY,
					   SKS_FUNC_STEP_UPDATE);
		break;
	case SKS_CMD_SIGN_FINAL:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_SIGN,
					   SKS_FUNC_STEP_FINAL);
		break;
	case SKS_CMD_VERIFY_FINAL:
		rc = entry_processing_step(teesess, ctrl, p1_in, p2_out,
					   SKS_FUNCTION_VERIFY,
					   SKS_FUNC_STEP_FINAL);
		break;

	case SKS_CMD_FIND_OBJECTS_INIT:
		rc = entry_find_objects_init(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_FIND_OBJECTS:
		rc = entry_find_objects(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_FIND_OBJECTS_FINAL:
		rc = entry_find_objects_final(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_GET_ATTRIBUTE_VALUE:
		rc = entry_get_attribute_value(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_INIT_PIN:
		rc = entry_init_pin(teesess, ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_SET_PIN:
		rc = entry_set_pin(teesess, ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_LOGIN:
		rc = entry_login(teesess, ctrl, p1_in, p2_out);
		break;
	case SKS_CMD_LOGOUT:
		rc = entry_logout(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_GENERATE_KEY_PAIR:
		rc = entry_generate_key_pair(teesess, ctrl, p1_in, p2_out);
		break;

	case SKS_CMD_DERIVE_KEY:
		rc = entry_derive_key(teesess, ctrl, p1_in, p2_out);
		break;

	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INOUT &&
	    ctrl->memref.size >= sizeof(uint32_t) &&
	    !((uintptr_t)ctrl->memref.buffer & 0x03UL)) {

		TEE_MemMove(ctrl->memref.buffer, &rc, sizeof(uint32_t));
		ctrl->memref.size = sizeof(uint32_t);

		res = sks2tee_noerr(rc);

		DMSG("SKS TA exit: %s rc 0x%08" PRIx32 "/%s",
			sks2str_skscmd(cmd), rc, sks2str_rc(rc));
	} else {
		res = sks2tee_error(rc);
		DMSG("SKS TA exit: %s rc 0x%08" PRIx32 "/%s, TEE rc %" PRIx32,
			sks2str_skscmd(cmd), rc, sks2str_rc(rc), res);
	}

	return res;

bad_types:
	DMSG("Bad parameter types used at SKS TA entry:");
	DMSG("- parameter #0: formated input request buffer or none");
	DMSG("- parameter #1: processed input data buffer or none");
	DMSG("- parameter #2: processed output data buffer or none");
	DMSG("- parameter #3: none");
	return TEE_ERROR_BAD_PARAMETERS;
}
