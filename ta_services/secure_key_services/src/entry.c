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
	uint32_t *ver;

	if (ctrl || in)
		return SKS_BAD_PARAM;

	if (!out)
		return SKS_OK;

	if (out->memref.size < 2 * sizeof(uint32_t))
		return SKS_SHORT_BUFFER;

	ver = (uint32_t *)out->memref.buffer;
	*ver = SKS_VERSION_ID0;
	*(ver + 1) = SKS_VERSION_ID1;

	return SKS_OK;
}

/*
 * Entry point for SKS TA commands
 *
 * ABI: param#0 is control buffer with serialazed arguments.
 *	param#1 is the input data buffer
 *	param#2 is the output data buffer (also used to return handles)
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
	TEE_Param *in = NULL;
	TEE_Param *out = NULL;
	uintptr_t teesess = (uintptr_t)tee_session;
	TEE_Result res;
	uint32_t rc;

	if (TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INOUT)
		ctrl = &params[0];
	else if (TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT)
		in = &params[1];
	else if (TEE_PARAM_TYPE_GET(ptypes, 1) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT)
		out = &params[2];
	else if (TEE_PARAM_TYPE_GET(ptypes, 2) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	DMSG("%s ctrl %" PRIu32 "@%p, in %" PRIu32 "@%p, out %" PRIu32 "@%p",
		sks2str_skscmd(cmd),
		ctrl ? ctrl->memref.size : 0, ctrl ? ctrl->memref.buffer : 0,
		in ? in->memref.size : 0, in ? in->memref.buffer : 0,
		out ? out->memref.size : 0, out ? out->memref.buffer : 0);

	switch (cmd) {
	case SKS_CMD_PING:
		rc = entry_ping(ctrl, in, out);
		break;

	case SKS_CMD_CK_SLOT_LIST:
		rc = entry_ck_slot_list(ctrl, in, out);
		break;
	case SKS_CMD_CK_SLOT_INFO:
		rc = entry_ck_slot_info(ctrl, in, out);
		break;
	case SKS_CMD_CK_TOKEN_INFO:
		rc = entry_ck_token_info(ctrl, in, out);
		break;
	case SKS_CMD_CK_INIT_TOKEN:
		rc = entry_ck_token_initialize(ctrl, in, out);
		break;

	case SKS_CMD_CK_MECHANISM_IDS:
		rc = entry_ck_token_mecha_ids(ctrl, in, out);
		break;
	case SKS_CMD_CK_MECHANISM_INFO:
		rc = entry_ck_token_mecha_info(ctrl, in, out);
		break;

	case SKS_CMD_CK_OPEN_RO_SESSION:
		rc = entry_ck_token_ro_session(teesess, ctrl, in, out);
		break;
	case SKS_CMD_CK_OPEN_RW_SESSION:
		rc = entry_ck_token_rw_session(teesess, ctrl, in, out);
		break;
	case SKS_CMD_CK_CLOSE_SESSION:
		rc = entry_ck_token_close_session(teesess, ctrl, in, out);
		break;
	case SKS_CMD_CK_CLOSE_ALL_SESSIONS:
		rc = entry_ck_token_close_all(teesess, ctrl, in, out);
		break;

	case SKS_CMD_IMPORT_OBJECT:
		rc = entry_import_object(teesess, ctrl, in, out);
		break;
	case SKS_CMD_DESTROY_OBJECT:
		rc = entry_destroy_object(teesess, ctrl, in, out);
		break;

	case SKS_CMD_ENCRYPT_INIT:
	case SKS_CMD_DECRYPT_INIT:
		rc = entry_cipher_init(teesess, ctrl, in, out,
					cmd == SKS_CMD_DECRYPT_INIT);
		break;
	case SKS_CMD_ENCRYPT_UPDATE:
	case SKS_CMD_DECRYPT_UPDATE:
		rc = entry_cipher_update(teesess, ctrl, in, out,
					 cmd == SKS_CMD_DECRYPT_UPDATE);
		break;
	case SKS_CMD_ENCRYPT_FINAL:
	case SKS_CMD_DECRYPT_FINAL:
		rc = entry_cipher_final(teesess, ctrl, in, out,
					cmd == SKS_CMD_DECRYPT_FINAL);
		break;

	case SKS_CMD_GENERATE_SYMM_KEY:
		rc = entry_generate_object(teesess, ctrl, in, out);
		break;

	case SKS_CMD_SIGN_INIT:
	case SKS_CMD_VERIFY_INIT:
		rc = entry_signverify_init(teesess, ctrl, in, out,
						cmd == SKS_CMD_SIGN_INIT);
		break;
	case SKS_CMD_SIGN_UPDATE:
	case SKS_CMD_VERIFY_UPDATE:
		rc = entry_signverify_update(teesess, ctrl, in, out,
						cmd == SKS_CMD_SIGN_UPDATE);
		break;
	case SKS_CMD_SIGN_FINAL:
	case SKS_CMD_VERIFY_FINAL:
		rc = entry_signverify_final(teesess, ctrl, in, out,
						cmd == SKS_CMD_SIGN_FINAL);
		break;

	case SKS_CMD_FIND_OBJECTS_INIT:
		rc = entry_find_objects_init(teesess, ctrl, in, out);
		break;

	case SKS_CMD_FIND_OBJECTS:
		rc = entry_find_objects(teesess, ctrl, in, out);
		break;

	case SKS_CMD_FIND_OBJECTS_FINAL:
		rc = entry_find_objects_final(teesess, ctrl, in, out);
		break;

	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INOUT &&
	    ctrl->memref.size >= sizeof(uint32_t)) {

		TEE_MemMove(ctrl->memref.buffer, &rc, sizeof(uint32_t));
		ctrl->memref.size = sizeof(uint32_t);

		res = sks2tee_noerr(rc);
	} else {
		res = sks2tee_error(rc);
	}

	DMSG("SKS TA exit: %s rc 0x%08" PRIu32 "/%s",
		sks2str_skscmd(cmd), rc, sks2str_rc(rc));

	return res;

bad_types:
	DMSG("Bad parameter types used at SKS TA entry:");
	DMSG("- parameter #0: formated input request buffer or none");
	DMSG("- parameter #1: processed input data buffer or none");
	DMSG("- parameter #2: processed output data buffer or none");
	DMSG("- parameter #3: none");
	return TEE_ERROR_BAD_PARAMETERS;
}
