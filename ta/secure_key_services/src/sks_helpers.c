// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <assert.h>
#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <tee_internal_api.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "processing.h"
#include "sks_helpers.h"

static const char __maybe_unused unknown[] = "<unknown-identifier>";

struct attr_size {
	uint32_t id;
	uint32_t size;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define SKS_ID_SZ(_id, _size)	{ .id = _id, .size = _size, .string = #_id }
#else
#define SKS_ID_SZ(_id, _size)	{ .id = _id, .size = _size }
#endif

static const struct attr_size attr_ids[] = {
	SKS_ID_SZ(SKS_CKA_CLASS, 4),
	SKS_ID_SZ(SKS_CKA_KEY_TYPE, 4),
	SKS_ID_SZ(SKS_CKA_VALUE, 0),
	SKS_ID_SZ(SKS_CKA_VALUE_LEN, 4),
	SKS_ID_SZ(SKS_CKA_LABEL, 0),
	SKS_ID_SZ(SKS_CKA_WRAP_TEMPLATE, 0),
	SKS_ID_SZ(SKS_CKA_UNWRAP_TEMPLATE, 0),
	SKS_ID_SZ(SKS_CKA_DERIVE_TEMPLATE, 0),
	SKS_ID_SZ(SKS_CKA_START_DATE, 4),
	SKS_ID_SZ(SKS_CKA_END_DATE, 4),
	SKS_ID_SZ(SKS_CKA_OBJECT_ID, 0),
	SKS_ID_SZ(SKS_CKA_APPLICATION, 0),
	SKS_ID_SZ(SKS_CKA_MECHANISM_TYPE, 4),
	SKS_ID_SZ(SKS_CKA_ID, 0),
	SKS_ID_SZ(SKS_CKA_ALLOWED_MECHANISMS, 0),
	SKS_ID_SZ(SKS_CKA_EC_POINT, 0),
	SKS_ID_SZ(SKS_CKA_EC_PARAMS, 0),
	SKS_ID_SZ(SKS_CKA_MODULUS, 0),
	SKS_ID_SZ(SKS_CKA_MODULUS_BITS, 4),
	SKS_ID_SZ(SKS_CKA_PUBLIC_EXPONENT, 0),
	SKS_ID_SZ(SKS_CKA_PRIVATE_EXPONENT, 0),
	SKS_ID_SZ(SKS_CKA_PRIME_1, 0),
	SKS_ID_SZ(SKS_CKA_PRIME_2, 0),
	SKS_ID_SZ(SKS_CKA_EXPONENT_1, 0),
	SKS_ID_SZ(SKS_CKA_EXPONENT_2, 0),
	SKS_ID_SZ(SKS_CKA_COEFFICIENT, 0),
	SKS_ID_SZ(SKS_CKA_SUBJECT, 0),
	SKS_ID_SZ(SKS_CKA_PUBLIC_KEY_INFO, 0),
	/* Below are boolean attributes */
	SKS_ID_SZ(SKS_CKA_TOKEN, 1),
	SKS_ID_SZ(SKS_CKA_PRIVATE, 1),
	SKS_ID_SZ(SKS_CKA_TRUSTED, 1),
	SKS_ID_SZ(SKS_CKA_SENSITIVE, 1),
	SKS_ID_SZ(SKS_CKA_ENCRYPT, 1),
	SKS_ID_SZ(SKS_CKA_DECRYPT, 1),
	SKS_ID_SZ(SKS_CKA_WRAP, 1),
	SKS_ID_SZ(SKS_CKA_UNWRAP, 1),
	SKS_ID_SZ(SKS_CKA_SIGN, 1),
	SKS_ID_SZ(SKS_CKA_SIGN_RECOVER, 1),
	SKS_ID_SZ(SKS_CKA_VERIFY, 1),
	SKS_ID_SZ(SKS_CKA_VERIFY_RECOVER, 1),
	SKS_ID_SZ(SKS_CKA_DERIVE, 1),
	SKS_ID_SZ(SKS_CKA_EXTRACTABLE, 1),
	SKS_ID_SZ(SKS_CKA_LOCAL, 1),
	SKS_ID_SZ(SKS_CKA_NEVER_EXTRACTABLE, 1),
	SKS_ID_SZ(SKS_CKA_ALWAYS_SENSITIVE, 1),
	SKS_ID_SZ(SKS_CKA_MODIFIABLE, 1),
	SKS_ID_SZ(SKS_CKA_COPYABLE, 1),
	SKS_ID_SZ(SKS_CKA_DESTROYABLE, 1),
	SKS_ID_SZ(SKS_CKA_ALWAYS_AUTHENTICATE, 1),
	SKS_ID_SZ(SKS_CKA_WRAP_WITH_TRUSTED, 1),
	/* Specific SKS attribute IDs */
	SKS_ID_SZ(SKS_UNDEFINED_ID, 0),
	SKS_ID_SZ(SKS_CKA_EC_POINT_X, 0),
	SKS_ID_SZ(SKS_CKA_EC_POINT_Y, 0),
};

struct processing_id {
	uint32_t id;
	bool supported;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define SKS_PROCESSING_ID(_id) \
			{ .id = _id, .supported = true, .string = #_id }
#define SKS_UNSUPPORTED_PROCESSING_ID(_id) \
			{ .id = _id, .supported = false, .string = #_id }
#else
#define SKS_PROCESSING_ID(_id) \
			{ .id = _id, .supported = true }
#define SKS_UNSUPPORTED_PROCESSING_ID(_id, _size) \
			{ .id = _id, .supported = false }

#endif

static const struct processing_id __maybe_unused processing_ids[] = {
	SKS_PROCESSING_ID(SKS_CKM_AES_ECB),
	SKS_PROCESSING_ID(SKS_CKM_AES_CBC),
	SKS_PROCESSING_ID(SKS_CKM_AES_CBC_PAD),
	SKS_PROCESSING_ID(SKS_CKM_AES_CTR),
	SKS_PROCESSING_ID(SKS_CKM_AES_GCM),
	SKS_PROCESSING_ID(SKS_CKM_AES_CCM),
	SKS_PROCESSING_ID(SKS_CKM_AES_CTS),
	SKS_PROCESSING_ID(SKS_CKM_AES_GMAC),
	SKS_PROCESSING_ID(SKS_CKM_AES_CMAC),
	SKS_PROCESSING_ID(SKS_CKM_AES_CMAC_GENERAL),
	SKS_PROCESSING_ID(SKS_CKM_AES_ECB_ENCRYPT_DATA),
	SKS_PROCESSING_ID(SKS_CKM_AES_CBC_ENCRYPT_DATA),
	SKS_PROCESSING_ID(SKS_CKM_AES_KEY_GEN),
	SKS_PROCESSING_ID(SKS_CKM_GENERIC_SECRET_KEY_GEN),
	SKS_PROCESSING_ID(SKS_CKM_MD5_HMAC),
	SKS_PROCESSING_ID(SKS_CKM_SHA_1_HMAC),
	SKS_PROCESSING_ID(SKS_CKM_SHA224_HMAC),
	SKS_PROCESSING_ID(SKS_CKM_SHA256_HMAC),
	SKS_PROCESSING_ID(SKS_CKM_SHA384_HMAC),
	SKS_PROCESSING_ID(SKS_CKM_SHA512_HMAC),
	SKS_PROCESSING_ID(SKS_CKM_AES_XCBC_MAC),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_EC_KEY_PAIR_GEN),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDSA),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDSA_SHA1),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDSA_SHA224),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDSA_SHA256),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDSA_SHA384),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDSA_SHA512),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDH1_DERIVE),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDH1_COFACTOR_DERIVE),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECMQV_DERIVE),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_ECDH_AES_KEY_WRAP),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_RSA_PKCS_KEY_PAIR_GEN),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_RSA_PKCS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_RSA_9796),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_RSA_X_509),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA1_RSA_PKCS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_RSA_PKCS_OAEP),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA1_RSA_PKCS_PSS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA256_RSA_PKCS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA384_RSA_PKCS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA512_RSA_PKCS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA256_RSA_PKCS_PSS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA384_RSA_PKCS_PSS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA512_RSA_PKCS_PSS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA224_RSA_PKCS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA224_RSA_PKCS_PSS),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_RSA_AES_KEY_WRAP),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_MD5),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA_1),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA224),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA256),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA384),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_CKM_SHA512),
	SKS_UNSUPPORTED_PROCESSING_ID(SKS_UNDEFINED_ID)
};

struct string_id {
	uint32_t id;
#if CFG_TEE_TA_LOG_LEVEL > 0
	const char *string;
#endif
};

#if CFG_TEE_TA_LOG_LEVEL > 0
#define SKS_ID(_id)		{ .id = _id, .string = #_id }
#else
#define SKS_ID(_id)		{ .id = _id }
#endif

static const struct string_id __maybe_unused string_cmd[] = {
	SKS_ID(SKS_CMD_PING),
	SKS_ID(SKS_CMD_CK_SLOT_LIST),
	SKS_ID(SKS_CMD_CK_SLOT_INFO),
	SKS_ID(SKS_CMD_CK_TOKEN_INFO),
	SKS_ID(SKS_CMD_CK_MECHANISM_IDS),
	SKS_ID(SKS_CMD_CK_MECHANISM_INFO),
	SKS_ID(SKS_CMD_CK_INIT_TOKEN),
	SKS_ID(SKS_CMD_CK_INIT_PIN),
	SKS_ID(SKS_CMD_CK_SET_PIN),
	SKS_ID(SKS_CMD_CK_OPEN_RO_SESSION),
	SKS_ID(SKS_CMD_CK_OPEN_RW_SESSION),
	SKS_ID(SKS_CMD_CK_CLOSE_SESSION),
	SKS_ID(SKS_CMD_CK_SESSION_INFO),
	SKS_ID(SKS_CMD_CK_CLOSE_ALL_SESSIONS),
	SKS_ID(SKS_CMD_IMPORT_OBJECT),
	SKS_ID(SKS_CMD_DESTROY_OBJECT),
	SKS_ID(SKS_CMD_ENCRYPT_INIT),
	SKS_ID(SKS_CMD_DECRYPT_INIT),
	SKS_ID(SKS_CMD_ENCRYPT_UPDATE),
	SKS_ID(SKS_CMD_DECRYPT_UPDATE),
	SKS_ID(SKS_CMD_ENCRYPT_FINAL),
	SKS_ID(SKS_CMD_DECRYPT_FINAL),
	SKS_ID(SKS_CMD_GENERATE_SYMM_KEY),
	SKS_ID(SKS_CMD_SIGN_INIT),
	SKS_ID(SKS_CMD_VERIFY_INIT),
	SKS_ID(SKS_CMD_SIGN_UPDATE),
	SKS_ID(SKS_CMD_VERIFY_UPDATE),
	SKS_ID(SKS_CMD_SIGN_FINAL),
	SKS_ID(SKS_CMD_VERIFY_FINAL),
	SKS_ID(SKS_CMD_FIND_OBJECTS_INIT),
	SKS_ID(SKS_CMD_FIND_OBJECTS),
	SKS_ID(SKS_CMD_FIND_OBJECTS_FINAL),
	SKS_ID(SKS_CMD_GET_OBJECT_SIZE),
	SKS_ID(SKS_CMD_GET_ATTRIBUTE_VALUE),
	SKS_ID(SKS_CMD_SET_ATTRIBUTE_VALUE),
	SKS_ID(SKS_CMD_DERIVE_KEY),
	SKS_ID(SKS_CMD_INIT_PIN),
	SKS_ID(SKS_CMD_SET_PIN),
	SKS_ID(SKS_CMD_LOGIN),
	SKS_ID(SKS_CMD_LOGOUT),
	SKS_ID(SKS_CMD_GENERATE_KEY_PAIR),
	SKS_ID(SKS_CMD_ENCRYPT_ONESHOT),
	SKS_ID(SKS_CMD_DECRYPT_ONESHOT),
	SKS_ID(SKS_CMD_SIGN_ONESHOT),
	SKS_ID(SKS_CMD_VERIFY_ONESHOT),
};

static const struct string_id __maybe_unused string_rc[] = {
	SKS_ID(SKS_CKR_OK),
	SKS_ID(SKS_CKR_GENERAL_ERROR),
	SKS_ID(SKS_CKR_DEVICE_MEMORY),
	SKS_ID(SKS_CKR_ARGUMENTS_BAD),
	SKS_ID(SKS_CKR_BUFFER_TOO_SMALL),
	SKS_ID(SKS_CKR_FUNCTION_FAILED),
	SKS_ID(SKS_CKR_SIGNATURE_INVALID),
	SKS_ID(SKS_CKR_ATTRIBUTE_TYPE_INVALID),
	SKS_ID(SKS_CKR_ATTRIBUTE_VALUE_INVALID),
	SKS_ID(SKS_CKR_OBJECT_HANDLE_INVALID),
	SKS_ID(SKS_CKR_KEY_HANDLE_INVALID),
	SKS_ID(SKS_CKR_MECHANISM_INVALID),
	SKS_ID(SKS_CKR_SESSION_HANDLE_INVALID),
	SKS_ID(SKS_CKR_SLOT_ID_INVALID),
	SKS_ID(SKS_CKR_MECHANISM_PARAM_INVALID),
	SKS_ID(SKS_CKR_TEMPLATE_INCONSISTENT),
	SKS_ID(SKS_CKR_TEMPLATE_INCOMPLETE),
	SKS_ID(SKS_CKR_PIN_INCORRECT),
	SKS_ID(SKS_CKR_PIN_LOCKED),
	SKS_ID(SKS_CKR_PIN_EXPIRED),
	SKS_ID(SKS_CKR_PIN_INVALID),
	SKS_ID(SKS_CKR_PIN_LEN_RANGE),
	SKS_ID(SKS_CKR_SESSION_EXISTS),
	SKS_ID(SKS_CKR_SESSION_READ_ONLY),
	SKS_ID(SKS_CKR_SESSION_READ_WRITE_SO_EXISTS),
	SKS_ID(SKS_CKR_OPERATION_ACTIVE),
	SKS_ID(SKS_CKR_KEY_FUNCTION_NOT_PERMITTED),
	SKS_ID(SKS_CKR_OPERATION_NOT_INITIALIZED),
	SKS_ID(SKS_CKR_TOKEN_WRITE_PROTECTED),
	SKS_ID(SKS_CKR_TOKEN_NOT_PRESENT),
	SKS_ID(SKS_CKR_TOKEN_NOT_RECOGNIZED),
	SKS_ID(SKS_CKR_ACTION_PROHIBITED),
	SKS_ID(SKS_CKR_ATTRIBUTE_READ_ONLY),
	SKS_ID(SKS_CKR_PIN_TOO_WEAK),
	SKS_ID(SKS_CKR_CURVE_NOT_SUPPORTED),
	SKS_ID(SKS_CKR_DOMAIN_PARAMS_INVALID),
	SKS_ID(SKS_CKR_USER_ALREADY_LOGGED_IN),
	SKS_ID(SKS_CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
	SKS_ID(SKS_CKR_USER_NOT_LOGGED_IN),
	SKS_ID(SKS_CKR_USER_PIN_NOT_INITIALIZED),
	SKS_ID(SKS_CKR_USER_TOO_MANY_TYPES),
	SKS_ID(SKS_CKR_USER_TYPE_INVALID),
	SKS_ID(SKS_CKR_SESSION_READ_ONLY_EXISTS),
	SKS_ID(SKS_NOT_FOUND),
	SKS_ID(SKS_NOT_IMPLEMENTED),
};

static const struct string_id __maybe_unused string_slot_flags[] = {
	SKS_ID(SKS_CKFS_TOKEN_PRESENT),
	SKS_ID(SKS_CKFS_REMOVABLE_DEVICE),
	SKS_ID(SKS_CKFS_HW_SLOT),
};

static const struct string_id __maybe_unused string_token_flags[] = {
	SKS_ID(SKS_CKFT_RNG),
	SKS_ID(SKS_CKFT_WRITE_PROTECTED),
	SKS_ID(SKS_CKFT_LOGIN_REQUIRED),
	SKS_ID(SKS_CKFT_USER_PIN_INITIALIZED),
	SKS_ID(SKS_CKFT_RESTORE_KEY_NOT_NEEDED),
	SKS_ID(SKS_CKFT_CLOCK_ON_TOKEN),
	SKS_ID(SKS_CKFT_PROTECTED_AUTHENTICATION_PATH),
	SKS_ID(SKS_CKFT_DUAL_CRYPTO_OPERATIONS),
	SKS_ID(SKS_CKFT_TOKEN_INITIALIZED),
	SKS_ID(SKS_CKFT_USER_PIN_COUNT_LOW),
	SKS_ID(SKS_CKFT_USER_PIN_FINAL_TRY),
	SKS_ID(SKS_CKFT_USER_PIN_LOCKED),
	SKS_ID(SKS_CKFT_USER_PIN_TO_BE_CHANGED),
	SKS_ID(SKS_CKFT_SO_PIN_COUNT_LOW),
	SKS_ID(SKS_CKFT_SO_PIN_FINAL_TRY),
	SKS_ID(SKS_CKFT_SO_PIN_LOCKED),
	SKS_ID(SKS_CKFT_SO_PIN_TO_BE_CHANGED),
	SKS_ID(SKS_CKFT_ERROR_STATE),
};

static const struct string_id __maybe_unused string_class[] = {
	SKS_ID(SKS_CKO_SECRET_KEY),
	SKS_ID(SKS_CKO_PUBLIC_KEY),
	SKS_ID(SKS_CKO_PRIVATE_KEY),
	SKS_ID(SKS_CKO_OTP_KEY),
	SKS_ID(SKS_CKO_CERTIFICATE),
	SKS_ID(SKS_CKO_DATA),
	SKS_ID(SKS_CKO_DOMAIN_PARAMETERS),
	SKS_ID(SKS_CKO_HW_FEATURE),
	SKS_ID(SKS_CKO_MECHANISM),
	SKS_ID(SKS_UNDEFINED_ID)
};

static const struct string_id __maybe_unused string_key_type[] = {
	SKS_ID(SKS_CKK_AES),
	SKS_ID(SKS_CKK_GENERIC_SECRET),
	SKS_ID(SKS_CKK_MD5_HMAC),
	SKS_ID(SKS_CKK_SHA_1_HMAC),
	SKS_ID(SKS_CKK_SHA224_HMAC),
	SKS_ID(SKS_CKK_SHA256_HMAC),
	SKS_ID(SKS_CKK_SHA384_HMAC),
	SKS_ID(SKS_CKK_SHA512_HMAC),
	SKS_ID(SKS_CKK_EC),
	SKS_ID(SKS_CKK_RSA),
	SKS_ID(SKS_UNDEFINED_ID)
};

/* Processing IDs not exported in the TA API */
static const struct string_id __maybe_unused string_internal_processing[] = {
	SKS_ID(SKS_PROCESSING_IMPORT),
	SKS_ID(SKS_PROCESSING_COPY),
};

static const struct string_id __maybe_unused string_proc_flags[] = {
	SKS_ID(SKS_CKFM_HW),
	SKS_ID(SKS_CKFM_ENCRYPT),
	SKS_ID(SKS_CKFM_DECRYPT),
	SKS_ID(SKS_CKFM_DIGEST),
	SKS_ID(SKS_CKFM_SIGN),
	SKS_ID(SKS_CKFM_SIGN_RECOVER),
	SKS_ID(SKS_CKFM_VERIFY),
	SKS_ID(SKS_CKFM_VERIFY_RECOVER),
	SKS_ID(SKS_CKFM_GENERATE),
	SKS_ID(SKS_CKFM_GENERATE_PAIR),
	SKS_ID(SKS_CKFM_WRAP),
	SKS_ID(SKS_CKFM_UNWRAP),
	SKS_ID(SKS_CKFM_DERIVE),
	SKS_ID(SKS_CKFM_EC_F_P),
	SKS_ID(SKS_CKFM_EC_F_2M),
	SKS_ID(SKS_CKFM_EC_ECPARAMETERS),
	SKS_ID(SKS_CKFM_EC_NAMEDCURVE),
	SKS_ID(SKS_CKFM_EC_UNCOMPRESS),
	SKS_ID(SKS_CKFM_EC_COMPRESS),
};

/*
 * Helper functions to analyse SKS identifiers
 */

size_t sks_attr_is_class(uint32_t attribute_id)
{
	if (attribute_id == SKS_CKA_CLASS)
		return sizeof(uint32_t);
	else
		return 0;
}

size_t sks_attr_is_type(uint32_t attribute_id)
{
	switch (attribute_id) {
	case SKS_CKA_KEY_TYPE:
	case SKS_CKA_MECHANISM_TYPE:
		return sizeof(uint32_t);
	default:
		return 0;
	}
}

bool sks_class_has_type(uint32_t class)
{
	switch (class) {
	case SKS_CKO_CERTIFICATE:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_MECHANISM:
	case SKS_CKO_HW_FEATURE:
		return 1;
	default:
		return 0;
	}
}

bool sks_attr_class_is_key(uint32_t class)
{
	switch (class) {
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
		return 1;
	default:
		return 0;
	}
}

/* Returns shift position or -1 on error */
int sks_attr2boolprop_shift(uint32_t attr)
{
	COMPILE_TIME_ASSERT(SKS_BOOLPROPS_BASE == 0);

	if (attr > SKS_BOOLPROPS_LAST)
		return -1;

	return attr;
}

/*
 * Conversion between SKS and GPD TEE return codes
 */

TEE_Result sks2tee_error(uint32_t rv)
{
	switch (rv) {
	case SKS_CKR_OK:
		return TEE_SUCCESS;

	case SKS_CKR_ARGUMENTS_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case SKS_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case SKS_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	default:
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result sks2tee_noerr(uint32_t rc)
{
	switch (rc) {
	case SKS_CKR_ARGUMENTS_BAD:
		return TEE_ERROR_BAD_PARAMETERS;

	case SKS_CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;

	case SKS_CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;

	case SKS_CKR_GENERAL_ERROR:
		return TEE_ERROR_GENERIC;

	default:
		return TEE_SUCCESS;
	}
}

uint32_t tee2sks_error(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return SKS_CKR_OK;

	case TEE_ERROR_BAD_PARAMETERS:
		return SKS_CKR_ARGUMENTS_BAD;

	case TEE_ERROR_OUT_OF_MEMORY:
		return SKS_CKR_DEVICE_MEMORY;

	case TEE_ERROR_SHORT_BUFFER:
		return SKS_CKR_BUFFER_TOO_SMALL;

	case TEE_ERROR_MAC_INVALID:
		return SKS_CKR_SIGNATURE_INVALID;

	default:
		return SKS_CKR_GENERAL_ERROR;
	}
}

bool valid_sks_attribute_id(uint32_t id, uint32_t size)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++) {
		if (id != attr_ids[n].id)
			continue;

		/* Check size matches if provided */
		return !attr_ids[n].size || size == attr_ids[n].size;
	}

	return false;
}

bool key_type_is_symm_key(uint32_t id)
{
	switch (id) {
	case SKS_CKK_AES:
	case SKS_CKK_GENERIC_SECRET:
	case SKS_CKK_MD5_HMAC:
	case SKS_CKK_SHA_1_HMAC:
	case SKS_CKK_SHA224_HMAC:
	case SKS_CKK_SHA256_HMAC:
	case SKS_CKK_SHA384_HMAC:
	case SKS_CKK_SHA512_HMAC:
		return true;
	default:
		return false;
	}
}

bool key_type_is_asymm_key(uint32_t id)
{
	switch (id) {
	case SKS_CKK_EC:
	case SKS_CKK_RSA:
		return true;
	default:
		return false;
	}
}

bool mechanism_is_valid(uint32_t id)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++)
		if (id == processing_ids[n].id)
			return true;

	return false;
}

bool mechanism_is_supported(uint32_t id)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++) {
		if (processing_ids[n].id == id)
			return processing_ids[n].supported;
	}

	return false;
}

size_t get_supported_mechanisms(uint32_t *array, size_t array_count)
{
	size_t n;
	size_t m;
	size_t count = 0;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++) {
		if (processing_ids[n].supported)
			count++;
	}

	if (array_count == 0)
		return count;

	if (array_count < count) {
		EMSG("Expect well sized array");
		return 0;
	}

	for (n = 0, m = 0; n < ARRAY_SIZE(processing_ids); n++) {
		if (processing_ids[n].supported) {
			array[m] = processing_ids[n].id;
			m++;
		}
	}

	assert(m == count);

	return m;
}

/* Initialize a TEE attribute for a target SKS attribute in an object */
bool sks2tee_load_attr(TEE_Attribute *tee_ref, uint32_t tee_id,
			struct sks_object *obj, uint32_t sks_id)
{
	void *a_ptr;
	size_t a_size;
	uint32_t data32;

	switch (tee_id) {
	case TEE_ATTR_ECC_PUBLIC_VALUE_X:
	case TEE_ATTR_ECC_PUBLIC_VALUE_Y:
		// FIXME: workaround until we get parse DER data
		break;
	case TEE_ATTR_ECC_CURVE:
		if (get_attribute_ptr(obj->attributes, SKS_CKA_EC_PARAMS,
					&a_ptr, &a_size)) {
			EMSG("Missing EC_PARAMS attribute");
			return false;
		}

		data32 = ec_params2tee_curve(a_ptr, a_size);

		TEE_InitValueAttribute(tee_ref, TEE_ATTR_ECC_CURVE, data32, 0);
		return true;

	default:
		break;
	}

	if (get_attribute_ptr(obj->attributes, sks_id, &a_ptr, &a_size))
		return false;

	TEE_InitRefAttribute(tee_ref, tee_id, a_ptr, a_size);

	return true;
}

/* Easy conversion between SKS function of TEE crypto mode */
void sks2tee_mode(uint32_t *tee_id, uint32_t function)
{
	switch (function) {
	case SKS_FUNCTION_ENCRYPT:
		*tee_id = TEE_MODE_ENCRYPT;
		break;
	case SKS_FUNCTION_DECRYPT:
		*tee_id = TEE_MODE_DECRYPT;
		break;
	case SKS_FUNCTION_SIGN:
		*tee_id = TEE_MODE_SIGN;
		break;
	case SKS_FUNCTION_VERIFY:
		*tee_id = TEE_MODE_VERIFY;
		break;
	case SKS_FUNCTION_DERIVE:
		*tee_id = TEE_MODE_DERIVE;
		break;
	default:
		TEE_Panic(function);
	}
}

#if CFG_TEE_TA_LOG_LEVEL > 0
/*
 * Convert a SKS ID into its label string
 */
const char *sks2str_attr(uint32_t id)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(attr_ids); n++) {
		if (id != attr_ids[n].id)
			continue;

		/* Skip SKS_ prefix */
		return (char *)attr_ids[n].string + strlen("SKS_CKA_");
	}

	return unknown;
}

static const char *sks2str_mechanism_type(uint32_t id)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(processing_ids); n++) {
		if (id != processing_ids[n].id)
			continue;

		/* Skip SKS_ prefix */
		return (char *)processing_ids[n].string + strlen("SKS_CKM_");
	}

	return unknown;
}

static const char *id2str(uint32_t id, const struct string_id *table,
			  size_t count, const char *prefix)
{
	size_t n;
	const char *str = NULL;

	for (n = 0; n < count; n++) {
		if (id != table[n].id)
			continue;

		str = table[n].string;

		/* Skip prefix provided matches found */
		if (prefix && !TEE_MemCompare(str, prefix, strlen(prefix)))
			str += strlen(prefix);

		return str;
	}

	return unknown;
}

#define ID2STR(id, table, prefix)	\
	id2str(id, table, ARRAY_SIZE(table), prefix)

const char *sks2str_class(uint32_t id)
{
	return ID2STR(id, string_class, "SKS_CKO_");
}

const char *sks2str_type(uint32_t id, uint32_t class)
{
	switch (class) {
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
		return sks2str_key_type(id);
	default:
		return unknown;
	}
}
const char *sks2str_key_type(uint32_t id)
{
	return ID2STR(id, string_key_type, "SKS_CKK_");
}

const char *sks2str_boolprop(uint32_t id)
{
	if (id < 64)
		return sks2str_attr(id);

	return unknown;
}

const char *sks2str_proc(uint32_t id)
{
	const char *str = ID2STR(id, string_internal_processing,
				 "SKS_PROCESSING_");

	if (str != unknown)
		return str;

	return sks2str_mechanism_type(id);
}

const char *sks2str_proc_flag(uint32_t id)
{
	return ID2STR(id, string_proc_flags, "SKS_CKFM_");
}

const char *sks2str_rc(uint32_t id)
{
	return ID2STR(id, string_rc, "SKS_CKR_");
}

const char *sks2str_skscmd(uint32_t id)
{
	return ID2STR(id, string_cmd, NULL);
}

const char *sks2str_slot_flag(uint32_t id)
{
	return ID2STR(id, string_slot_flags, "SKS_CKFS_");
}

const char *sks2str_token_flag(uint32_t id)
{
	return ID2STR(id, string_token_flags, "SKS_CKFT_");
}

const char *sks2str_attr_value(uint32_t id, size_t size, void *value)
{
	static const char str_true[] = "TRUE";
	static const char str_false[] = "FALSE";
	static const char str_unkwon[] = "*";
	uint32_t type;

	if (sks_attr2boolprop_shift(id) >= 0)
		return !!*(uint8_t *)value ? str_true : str_false;

	if (size < sizeof(uint32_t))
		return str_unkwon;

	TEE_MemMove(&type, value, sizeof(uint32_t));

	if (sks_attr_is_class(id))
		return sks2str_class(type);

	if (id == SKS_CKA_KEY_TYPE)
		return sks2str_key_type(type);

	if (id == SKS_CKA_MECHANISM_TYPE)
		return sks2str_mechanism_type(type);

	return str_unkwon;
}

#endif /*CFG_TEE_TA_LOG_LEVEL*/
