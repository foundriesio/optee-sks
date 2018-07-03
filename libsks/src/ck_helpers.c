/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

#include "ck_helpers.h"
#include "local_utils.h"

/*
 * SKS TA returns Cryptoki like information structure.
 * These routine convert the SKS format structure and bit flags
 * from/into Cryptoki format structures and bit flags.
 */
#define MEMCPY_FIELD(_dst, _src, _f) \
	do { \
		memcpy((_dst)->_f, (_src)->_f, sizeof((_dst)->_f)); \
		if (sizeof((_dst)->_f) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)

#define MEMCPY_VERSION(_dst, _src, _f) \
	do { \
		memcpy(&(_dst)->_f, (_src)->_f, sizeof(CK_VERSION)); \
		if (sizeof(CK_VERSION) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)

static CK_RV sks2ck_slot_flags(CK_SLOT_INFO_PTR ck_info,
				struct sks_slot_info *sks_info)
{
	CK_FLAGS ck_flag;
	uint32_t sks_mask;

	ck_info->flags = 0;
	for (sks_mask = 1; sks_mask; sks_mask <<= 1) {

		/* Skip sks token flags without a CK equilavent */
		if (sks2ck_slot_flag(&ck_flag, sks_mask))
			continue;

		if (sks_info->flags & sks_mask)
			ck_info->flags |= ck_flag;
	}

	return CKR_OK;
}

CK_RV sks2ck_slot_info(CK_SLOT_INFO_PTR ck_info,
			struct sks_slot_info *sks_info)
{
	CK_RV rv;

	MEMCPY_FIELD(ck_info, sks_info, slotDescription);
	MEMCPY_FIELD(ck_info, sks_info, manufacturerID);

	rv = sks2ck_slot_flags(ck_info, sks_info);
	if (rv)
		return rv;

	MEMCPY_VERSION(ck_info, sks_info, hardwareVersion);
	MEMCPY_VERSION(ck_info, sks_info, firmwareVersion);

	return CKR_OK;
}

static CK_RV sks2ck_token_flags(CK_TOKEN_INFO_PTR ck_info,
				struct sks_token_info *sks_info)
{
	CK_FLAGS ck_flag;
	uint32_t sks_mask;

	ck_info->flags = 0;
	for (sks_mask = 1; sks_mask; sks_mask <<= 1) {

		/* Skip sks token flags without a CK equilavent */
		if (sks2ck_token_flag(&ck_flag, sks_mask))
			continue;

		if (sks_info->flags & sks_mask)
			ck_info->flags |= ck_flag;
	}

	return CKR_OK;
}

CK_RV sks2ck_token_info(CK_TOKEN_INFO_PTR ck_info,
			struct sks_token_info *sks_info)
{
	CK_RV rv;

	MEMCPY_FIELD(ck_info, sks_info, label);
	MEMCPY_FIELD(ck_info, sks_info, manufacturerID);
	MEMCPY_FIELD(ck_info, sks_info, model);
	MEMCPY_FIELD(ck_info, sks_info, serialNumber);

	rv = sks2ck_token_flags(ck_info, sks_info);
	if (rv)
		return rv;

	ck_info->ulMaxSessionCount = sks_info->ulMaxSessionCount;
	ck_info->ulSessionCount = sks_info->ulSessionCount;
	ck_info->ulMaxRwSessionCount = sks_info->ulMaxRwSessionCount;
	ck_info->ulRwSessionCount = sks_info->ulRwSessionCount;
	ck_info->ulMaxPinLen = sks_info->ulMaxPinLen;
	ck_info->ulMinPinLen = sks_info->ulMinPinLen;
	ck_info->ulTotalPublicMemory = sks_info->ulTotalPublicMemory;
	ck_info->ulFreePublicMemory = sks_info->ulFreePublicMemory;
	ck_info->ulTotalPrivateMemory = sks_info->ulTotalPrivateMemory;
	ck_info->ulFreePrivateMemory = sks_info->ulFreePrivateMemory;
	MEMCPY_VERSION(ck_info, sks_info, hardwareVersion);
	MEMCPY_VERSION(ck_info, sks_info, firmwareVersion);
	MEMCPY_FIELD(ck_info, sks_info, utcTime);

	return CKR_OK;
}

/*
 * Helpers for CK/SKS conversions: tables of identifiers
 */
struct ck2sks {
	CK_ULONG ck;
	uint32_t sks;
};

#define CK_SKS_ID(ck_id, sks_id)	{ .ck = ck_id, .sks = sks_id }

#define SKS2CK(out, in, conv)		sks2ck(out, in, conv, ARRAY_SIZE(conv))
#define CK2SKS(out, in, conv)		ck2sks(out, in, conv, ARRAY_SIZE(conv))

static int sks2ck(CK_ULONG *out, uint32_t id,
		  const struct ck2sks *conv, size_t count)
{
	size_t n;

	for (n = 0; n < count; n++) {
		if (id == conv[n].sks) {
			*out = conv[n].ck;
			return 0;
		}
	}

	return -1;
}

static int ck2sks(uint32_t *out, CK_ULONG id,
		  const struct ck2sks *conv, size_t count)
{
	size_t n;

	for (n = 0; n < count; n++) {
		if (id == conv[n].ck) {
			*out = conv[n].sks;
			return 0;
		}
	}

	return -1;
}

/*
 * Identifiers and bit flags convertion tables
 */
static const struct ck2sks error_code[] = {
	CK_SKS_ID(CKR_OK,			SKS_CKR_OK),
	CK_SKS_ID(CKR_GENERAL_ERROR,		SKS_CKR_GENERAL_ERROR),
	CK_SKS_ID(CKR_DEVICE_MEMORY,		SKS_CKR_DEVICE_MEMORY),
	CK_SKS_ID(CKR_ARGUMENTS_BAD,		SKS_CKR_ARGUMENT_BAD),
	CK_SKS_ID(CKR_BUFFER_TOO_SMALL,		SKS_CKR_BUFFER_TOO_SMALL),
	CK_SKS_ID(CKR_FUNCTION_FAILED,		SKS_CKR_FUNCTION_FAILED),
	CK_SKS_ID(CKR_ATTRIBUTE_TYPE_INVALID,	SKS_CKR_ATTRIBUTE_TYPE_INVALID),
	CK_SKS_ID(CKR_ATTRIBUTE_VALUE_INVALID,	SKS_CKR_ATTRIBUTE_VALUE_INVALID),
	CK_SKS_ID(CKR_OBJECT_HANDLE_INVALID,	SKS_CKR_OBJECT_HANDLE_INVALID),
	CK_SKS_ID(CKR_KEY_HANDLE_INVALID,	SKS_CKR_KEY_HANDLE_INVALID),
	CK_SKS_ID(CKR_MECHANISM_INVALID,	SKS_CKR_MECHANISM_INVALID),
	CK_SKS_ID(CKR_SLOT_ID_INVALID,		SKS_CKR_SLOT_ID_INVALID),
	CK_SKS_ID(CKR_SESSION_HANDLE_INVALID,	SKS_CKR_SESSION_HANDLE_INVALID),
	CK_SKS_ID(CKR_PIN_INCORRECT,		SKS_CKR_PIN_INCORRECT),
	CK_SKS_ID(CKR_PIN_LOCKED,		SKS_CKR_PIN_LOCKED),
	CK_SKS_ID(CKR_PIN_EXPIRED,		SKS_CKR_PIN_EXPIRED),
	CK_SKS_ID(CKR_PIN_INVALID,		SKS_CKR_PIN_INVALID),
	CK_SKS_ID(CKR_OPERATION_ACTIVE,		SKS_CKR_OPERATION_ACTIVE),
	CK_SKS_ID(CKR_KEY_FUNCTION_NOT_PERMITTED,
					SKS_CKR_KEY_FUNCTION_NOT_PERMITTED),
	CK_SKS_ID(CKR_OPERATION_NOT_INITIALIZED,
					SKS_CKR_OPERATION_NOT_INITIALIZED),
	CK_SKS_ID(CKR_SESSION_READ_ONLY,	SKS_CKR_SESSION_READ_ONLY),
	CK_SKS_ID(CKR_MECHANISM_PARAM_INVALID,	SKS_CKR_MECHANISM_PARAM_INVALID),
	CK_SKS_ID(CK_VENDOR_INVALID_ID,		SKS_UNDEFINED_ID),
};

static const struct ck2sks slot_flag[] = {
	CK_SKS_ID(CKF_TOKEN_PRESENT,		SKS_CKFS_TOKEN_PRESENT),
	CK_SKS_ID(CKF_REMOVABLE_DEVICE,		SKS_CKFS_REMOVABLE_DEVICE),
	CK_SKS_ID(CKF_HW_SLOT,			SKS_CKFS_HW_SLOT),
};

static const struct ck2sks token_flag[] = {
	CK_SKS_ID(CKF_RNG,				SKS_CKFT_RNG),
	CK_SKS_ID(CKF_WRITE_PROTECTED,			SKS_CKFT_WRITE_PROTECTED),
	CK_SKS_ID(CKF_LOGIN_REQUIRED,			SKS_CKFT_LOGIN_REQUIRED),
	CK_SKS_ID(CKF_USER_PIN_INITIALIZED,		SKS_CKFT_USER_PIN_INITIALIZED),
	CK_SKS_ID(CKF_RESTORE_KEY_NOT_NEEDED,		SKS_CKFT_RESTORE_KEY_NOT_NEEDED),
	CK_SKS_ID(CKF_CLOCK_ON_TOKEN,			SKS_CKFT_CLOCK_ON_TOKEN),
	CK_SKS_ID(CKF_PROTECTED_AUTHENTICATION_PATH,	SKS_CKFT_PROTECTED_AUTHENTICATION_PATH),
	CK_SKS_ID(CKF_DUAL_CRYPTO_OPERATIONS,		SKS_CKFT_DUAL_CRYPTO_OPERATIONS),
	CK_SKS_ID(CKF_TOKEN_INITIALIZED,		SKS_CKFT_TOKEN_INITIALIZED),
	CK_SKS_ID(CKF_USER_PIN_COUNT_LOW,		SKS_CKFT_USER_PIN_COUNT_LOW),
	CK_SKS_ID(CKF_USER_PIN_FINAL_TRY,		SKS_CKFT_USER_PIN_FINAL_TRY),
	CK_SKS_ID(CKF_USER_PIN_LOCKED,			SKS_CKFT_USER_PIN_LOCKED),
	CK_SKS_ID(CKF_USER_PIN_TO_BE_CHANGED,		SKS_CKFT_USER_PIN_TO_BE_CHANGED),
	CK_SKS_ID(CKF_SO_PIN_COUNT_LOW,			SKS_CKFT_SO_PIN_COUNT_LOW),
	CK_SKS_ID(CKF_SO_PIN_FINAL_TRY,			SKS_CKFT_SO_PIN_FINAL_TRY),
	CK_SKS_ID(CKF_SO_PIN_LOCKED,			SKS_CKFT_SO_PIN_LOCKED),
	CK_SKS_ID(CKF_SO_PIN_TO_BE_CHANGED,		SKS_CKFT_SO_PIN_TO_BE_CHANGED),
	CK_SKS_ID(CKF_ERROR_STATE,			SKS_CKFT_ERROR_STATE),
};

static const struct ck2sks attribute_id[] = {
	CK_SKS_ID(CKA_CLASS,			SKS_CKA_CLASS),
	CK_SKS_ID(CKA_KEY_TYPE,			SKS_CKA_KEY_TYPE),
	CK_SKS_ID(CKA_VALUE,			SKS_CKA_VALUE),
	CK_SKS_ID(CKA_VALUE_LEN,		SKS_CKA_VALUE_LEN),
	CK_SKS_ID(CKA_WRAP_TEMPLATE,		SKS_CKA_WRAP_TEMPLATE),
	CK_SKS_ID(CKA_UNWRAP_TEMPLATE,		SKS_CKA_UNWRAP_TEMPLATE),
	CK_SKS_ID(CKA_DERIVE_TEMPLATE,		SKS_CKA_DERIVE_TEMPLATE),
	CK_SKS_ID(CKA_START_DATE,		SKS_CKA_START_DATE),
	CK_SKS_ID(CKA_END_DATE,			SKS_CKA_END_DATE),
	CK_SKS_ID(CKA_OBJECT_ID,		SKS_CKA_OBJECT_ID),
	CK_SKS_ID(CKA_APPLICATION,		SKS_CKA_APPLICATION),
	CK_SKS_ID(CKA_MECHANISM_TYPE,		SKS_CKA_MECHANISM_TYPE),
	CK_SKS_ID(CKA_ID,			SKS_CKA_ID),
	CK_SKS_ID(CKA_ALLOWED_MECHANISMS,	SKS_CKA_ALLOWED_MECHANISMS),
	/* Below are boolean attributes */\
	CK_SKS_ID(CKA_TOKEN,			SKS_CKA_TOKEN),
	CK_SKS_ID(CKA_PRIVATE,			SKS_CKA_PRIVATE),
	CK_SKS_ID(CKA_TRUSTED,			SKS_CKA_TRUSTED),
	CK_SKS_ID(CKA_SENSITIVE,		SKS_CKA_SENSITIVE),
	CK_SKS_ID(CKA_ENCRYPT,			SKS_CKA_ENCRYPT),
	CK_SKS_ID(CKA_DECRYPT,			SKS_CKA_DECRYPT),
	CK_SKS_ID(CKA_WRAP,			SKS_CKA_WRAP),
	CK_SKS_ID(CKA_UNWRAP,			SKS_CKA_UNWRAP),
	CK_SKS_ID(CKA_SIGN,			SKS_CKA_SIGN),
	CK_SKS_ID(CKA_SIGN_RECOVER,		SKS_CKA_SIGN_RECOVER),
	CK_SKS_ID(CKA_VERIFY,			SKS_CKA_VERIFY),
	CK_SKS_ID(CKA_VERIFY_RECOVER,		SKS_CKA_VERIFY_RECOVER),
	CK_SKS_ID(CKA_DERIVE,			SKS_CKA_DERIVE),
	CK_SKS_ID(CKA_EXTRACTABLE,		SKS_CKA_EXTRACTABLE),
	CK_SKS_ID(CKA_LOCAL,			SKS_CKA_LOCAL),
	CK_SKS_ID(CKA_NEVER_EXTRACTABLE,	SKS_CKA_NEVER_EXTRACTABLE),
	CK_SKS_ID(CKA_ALWAYS_SENSITIVE,		SKS_CKA_ALWAYS_SENSITIVE),
	CK_SKS_ID(CKA_MODIFIABLE,		SKS_CKA_MODIFIABLE),
	CK_SKS_ID(CKA_COPYABLE,			SKS_CKA_COPYABLE),
	CK_SKS_ID(CKA_DESTROYABLE,		SKS_CKA_DESTROYABLE),
	CK_SKS_ID(CKA_ALWAYS_AUTHENTICATE,	SKS_CKA_ALWAYS_AUTHENTICATE),
	CK_SKS_ID(CKA_WRAP_WITH_TRUSTED,	SKS_CKA_WRAP_WITH_TRUSTED),
	/* Specifc SKS attribute IDs */
	CK_SKS_ID(CK_VENDOR_INVALID_ID,		SKS_UNDEFINED_ID),
};

static const struct ck2sks mechanism_type[] = {
	CK_SKS_ID(CKM_AES_ECB,		SKS_CKM_AES_ECB),
	CK_SKS_ID(CKM_AES_CBC,		SKS_CKM_AES_CBC),
	CK_SKS_ID(CKM_AES_CBC_PAD,	SKS_CKM_AES_CBC_PAD),
	CK_SKS_ID(CKM_AES_CTR,		SKS_CKM_AES_CTR),
	CK_SKS_ID(CKM_AES_GCM,		SKS_CKM_AES_GCM),
	CK_SKS_ID(CKM_AES_CCM,		SKS_CKM_AES_CCM),
	CK_SKS_ID(CKM_AES_CTS,		SKS_CKM_AES_CTS),
	CK_SKS_ID(CKM_AES_GMAC,		SKS_CKM_AES_GMAC),
	CK_SKS_ID(CKM_AES_CMAC,		SKS_CKM_AES_CMAC),
	CK_SKS_ID(CKM_AES_CMAC_GENERAL,		SKS_CKM_AES_CMAC_GENERAL),
	CK_SKS_ID(CKM_AES_ECB_ENCRYPT_DATA,	SKS_CKM_AES_ECB_ENCRYPT_DATA),
	CK_SKS_ID(CKM_AES_CBC_ENCRYPT_DATA,	SKS_CKM_AES_CBC_ENCRYPT_DATA),
	CK_SKS_ID(CKM_AES_KEY_GEN,		SKS_CKM_AES_KEY_GEN),
	CK_SKS_ID(CKM_AES_XCBC_MAC,	SKS_CKM_AES_XCBC_MAC),

	CK_SKS_ID(CKM_GENERIC_SECRET_KEY_GEN,	SKS_CKM_GENERIC_SECRET_KEY_GEN),

	CK_SKS_ID(CKM_MD5_HMAC,		SKS_CKM_MD5_HMAC),
	CK_SKS_ID(CKM_SHA_1_HMAC,	SKS_CKM_SHA_1_HMAC),
	CK_SKS_ID(CKM_SHA224_HMAC,	SKS_CKM_SHA224_HMAC),
	CK_SKS_ID(CKM_SHA256_HMAC,	SKS_CKM_SHA256_HMAC),
	CK_SKS_ID(CKM_SHA384_HMAC,	SKS_CKM_SHA384_HMAC),
	CK_SKS_ID(CKM_SHA512_HMAC,	SKS_CKM_SHA512_HMAC),

	CK_SKS_ID(CK_VENDOR_INVALID_ID,	SKS_UNDEFINED_ID),
};

static const struct ck2sks mechanism_flag[] = {
	CK_SKS_ID(CKF_HW,			SKS_CKFM_HW),
	CK_SKS_ID(CKF_ENCRYPT,			SKS_CKFM_ENCRYPT),
	CK_SKS_ID(CKF_DECRYPT,			SKS_CKFM_DECRYPT),
	CK_SKS_ID(CKF_DIGEST,			SKS_CKFM_DIGEST),
	CK_SKS_ID(CKF_SIGN,			SKS_CKFM_SIGN),
	CK_SKS_ID(CKF_SIGN_RECOVER,		SKS_CKFM_SIGN_RECOVER),
	CK_SKS_ID(CKF_VERIFY,			SKS_CKFM_VERIFY),
	CK_SKS_ID(CKF_VERIFY_RECOVER,		SKS_CKFM_VERIFY_RECOVER),
	CK_SKS_ID(CKF_GENERATE,			SKS_CKFM_GENERATE),
	CK_SKS_ID(CKF_GENERATE_KEY_PAIR,	SKS_CKFM_GENERATE_PAIR),
	CK_SKS_ID(CKF_WRAP,			SKS_CKFM_WRAP),
	CK_SKS_ID(CKF_UNWRAP,			SKS_CKFM_UNWRAP),
	CK_SKS_ID(CKF_DERIVE,			SKS_CKFM_DERIVE),
};

static const struct ck2sks class_id[] = {
	CK_SKS_ID(CKO_SECRET_KEY,		SKS_CKO_SECRET_KEY),
	CK_SKS_ID(CKO_PUBLIC_KEY,		SKS_CKO_PUBLIC_KEY),
	CK_SKS_ID(CKO_PRIVATE_KEY,		SKS_CKO_PRIVATE_KEY),
	CK_SKS_ID(CKO_OTP_KEY,			SKS_CKO_OTP_KEY),
	CK_SKS_ID(CKO_CERTIFICATE,		SKS_CKO_CERTIFICATE),
	CK_SKS_ID(CKO_DATA,			SKS_CKO_DATA),
	CK_SKS_ID(CKO_DOMAIN_PARAMETERS,	SKS_CKO_DOMAIN_PARAMETERS),
	CK_SKS_ID(CKO_HW_FEATURE,		SKS_CKO_HW_FEATURE),
	CK_SKS_ID(CKO_MECHANISM,		SKS_CKO_MECHANISM),
	CK_SKS_ID(CK_VENDOR_INVALID_ID,		SKS_UNDEFINED_ID),
};

static const struct ck2sks key_type_id[] = {
	CK_SKS_ID(CKK_AES,			SKS_CKK_AES),
	CK_SKS_ID(CKK_GENERIC_SECRET,		SKS_CKK_GENERIC_SECRET),
	CK_SKS_ID(CKK_MD5_HMAC,			SKS_CKK_MD5_HMAC),
	CK_SKS_ID(CKK_SHA_1_HMAC,		SKS_CKK_SHA_1_HMAC),
	CK_SKS_ID(CKK_SHA224_HMAC,		SKS_CKK_SHA224_HMAC),
	CK_SKS_ID(CKK_SHA256_HMAC,		SKS_CKK_SHA256_HMAC),
	CK_SKS_ID(CKK_SHA384_HMAC,		SKS_CKK_SHA384_HMAC),
	CK_SKS_ID(CKK_SHA512_HMAC,		SKS_CKK_SHA512_HMAC),
	CK_SKS_ID(CK_VENDOR_INVALID_ID,		SKS_UNDEFINED_ID),
};

CK_RV sks2ck_rv(uint32_t sks)
{
	CK_ULONG rv;

	if (SKS2CK(&rv, sks, error_code))
		return CKR_GENERAL_ERROR;

	return (CK_RV)rv;
}

CK_RV sks2ck_slot_flag(CK_FLAGS *ck, uint32_t sks)
{
	CK_ULONG *flag = (CK_ULONG *)ck;

	if (SKS2CK(flag, sks, slot_flag))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

CK_RV sks2ck_token_flag(CK_FLAGS *ck, uint32_t sks)
{
	CK_ULONG *flag = (CK_ULONG *)ck;

	if (SKS2CK(flag, sks, token_flag))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

uint32_t ck2sks_attribute_id(CK_ULONG ck)
{
	uint32_t id;

	if (CK2SKS(&id, ck, attribute_id))
		return SKS_UNDEFINED_ID;

	return id;
}

CK_RV sks2ck_attribute_id(CK_ULONG *ck, uint32_t sks)
{
	if (SKS2CK(ck, sks, attribute_id))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

uint32_t ck2sks_mechanism_type(CK_MECHANISM_TYPE ck)
{
	uint32_t id;

	if (CK2SKS(&id, ck, mechanism_type))
		return SKS_UNDEFINED_ID;

	return id;
}

CK_RV sks2ck_mechanism_type(CK_MECHANISM_TYPE *ck, uint32_t sks)
{
	CK_ULONG *id = (CK_ULONG *)ck;

	if (SKS2CK(id, sks, mechanism_type))
		return CKR_MECHANISM_INVALID;

	return CKR_OK;
}

CK_RV teec2ck_rv(TEEC_Result res)
{
	switch (res) {
	case TEEC_SUCCESS:
		return CKR_OK;
	case TEEC_ERROR_OUT_OF_MEMORY:
		return CKR_DEVICE_MEMORY;
	case TEEC_ERROR_BAD_PARAMETERS:
		return CKR_ARGUMENTS_BAD;
	case TEEC_ERROR_SHORT_BUFFER:
		return CKR_BUFFER_TOO_SMALL;
	default:
		return CKR_FUNCTION_FAILED;
	}
}

/* Convert a array of mechanism type from sks into CK_MECHANIMS_TYPE */
CK_RV sks2ck_mechanism_type_list(CK_MECHANISM_TYPE *dst,
				 void *src, size_t count)
{
	CK_MECHANISM_TYPE *ck = dst;
	char *sks = src;
	size_t n;
	uint32_t proc;

	for (n = 0; n < count; n++, sks += sizeof(uint32_t), ck++) {
		memcpy(&proc, src, sizeof(proc));
		if (sks2ck_mechanism_type(ck, proc))
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}


CK_RV sks2ck_mechanism_flag(CK_FLAGS *ck, uint32_t sks)
{
	CK_ULONG *id = (CK_ULONG *)ck;

	if (SKS2CK(id, sks, mechanism_flag))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}


uint32_t ck2sks_class(CK_ULONG ck)
{
	uint32_t id;

	if (CK2SKS(&id, ck, class_id))
		return SKS_UNDEFINED_ID;

	return id;
}

CK_RV sks2ck_class(CK_ULONG *ck, uint32_t sks)
{
	if (SKS2CK(ck, sks, class_id))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

uint32_t ck2sks_key_type(CK_ULONG ck)
{
	uint32_t id;

	if (CK2SKS(&id, ck, key_type_id))
		return SKS_UNDEFINED_ID;

	return id;
}

CK_RV sks2ck_key_type(CK_ULONG *ck, uint32_t sks)
{
	if (SKS2CK(ck, sks, key_type_id))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

#include <stdio.h>

/* Convert structure CK_MECHANIMS_INFO from sks to ck (3 ulong fields) */
CK_RV sks2ck_mechanism_info(CK_MECHANISM_INFO *info, void *src)
{
	struct sks_mechanism_info sks;
	CK_FLAGS ck_flag;
	uint32_t mask;
	CK_RV rv;

	memcpy(&sks, src, sizeof(sks));

	info->ulMinKeySize = sks.min_key_size;
	info->ulMaxKeySize = sks.max_key_size;

	info->flags = 0;
	for (mask = 1; mask; mask <<= 1) {
		if (!(sks.flags & mask))
			continue;

		rv = sks2ck_mechanism_flag(&ck_flag, mask);
		if (rv)
			return rv;

		info->flags |= ck_flag;
	}

	return CKR_OK;
}

/*
 * Helper functions to analyse CK fields
 */
size_t ck_attr_is_class(uint32_t id)
{
	if (id == CKA_CLASS)
		return sizeof(CK_ULONG);
	else
		return 0;
}

size_t ck_attr_is_type(uint32_t id)
{
	switch (id) {
	case CKA_CERTIFICATE_TYPE:
	case CKA_KEY_TYPE:
	case CKA_HW_FEATURE_TYPE:
	case CKA_MECHANISM_TYPE:
		return sizeof(CK_ULONG);
	default:
		return 0;
	}
}
int sks_object_has_boolprop(uint32_t class)
{
	switch (class) {
	case SKS_CKO_DATA:
	case SKS_CKO_CERTIFICATE:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_DOMAIN_PARAMETERS:
		return 1;
	default:
		return 0;
	}
}
int sks_class_has_type(uint32_t class)
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

uint32_t ck2sks_type_in_class(CK_ULONG ck, CK_ULONG class)
{
	switch (class) {
	case CKO_DATA:
		return 0;
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_OTP_KEY:
		return ck2sks_key_type(ck);
	case CKO_MECHANISM:
		return ck2sks_mechanism_type(ck);
	case CKO_CERTIFICATE:
	default:
		return SKS_UNDEFINED_ID;
	}
}

CK_RV sks2ck_type_in_class(CK_ULONG *ck, uint32_t sks, CK_ULONG class)
{
	switch (class) {
	case SKS_CKO_DATA:
		return CKR_NO_EVENT;
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
	case SKS_CKO_OTP_KEY:
		return sks2ck_key_type(ck, sks);
	case SKS_CKO_MECHANISM:
		return sks2ck_mechanism_type(ck, sks);
	case SKS_CKO_CERTIFICATE:
	default:
		return CKR_GENERAL_ERROR;
	}
}

