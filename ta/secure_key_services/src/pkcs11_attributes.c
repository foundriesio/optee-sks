/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "attributes.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "sks_helpers.h"

/* Byte size of CKA_ID attribute when generated locally */
#define SKS_CKA_DEFAULT_SIZE		16

struct pkcs11_mechachism_modes {
	uint32_t id;
	uint32_t flags;
	bool available;
	bool one_shot;
};

/*
 * SKS_CKFM_EC_F_P
 * SKS_CKFM_EC_F_2M
 * SKS_CKFM_EC_ECPARAMETERS
 * SKS_CKFM_EC_NAMEDCURVE
 * SKS_CKFM_EC_UNCOMPRESS
 * SKS_CKFM_EC_COMPRESS
 */
#define SKS_ECM		0

/* SKS_CKFM_HW: need to ask core one HW support of the mechanisms */
#define SKS_M(_label, _dig, _enc, _dec, _sig, _ver,		\
		_sr, _vr, _der, _wra, _unw, _gen, _gpa, _1s)	\
	{							\
		.id = SKS_CKM_  ## _label,			\
		.one_shot = _1s,				\
		.flags = (_enc ? SKS_CKFM_ENCRYPT : 0) |	\
			(_dec ? SKS_CKFM_DECRYPT : 0) |		\
			(_dig ? SKS_CKFM_DIGEST : 0) |		\
			(_sig ? SKS_CKFM_SIGN : 0) |		\
			(_sr ? SKS_CKFM_SIGN_RECOVER : 0) |	\
			(_ver ? SKS_CKFM_VERIFY : 0) |		\
			(_vr ? SKS_CKFM_VERIFY_RECOVER : 0) |	\
			(_gen ? SKS_CKFM_GENERATE : 0) |	\
			(_gpa ? SKS_CKFM_GENERATE_PAIR : 0) |	\
			(_wra ? SKS_CKFM_WRAP : 0) |		\
			(_unw ? SKS_CKFM_UNWRAP : 0) |		\
			(_der ? SKS_CKFM_DERIVE : 0) |		\
			SKS_ECM,				\
	}

static const __maybe_unused struct pkcs11_mechachism_modes pkcs11_modes[] = {
	/*
	 * PKCS#11 directives on mechanism support for the several processing
	 * modes.
	 *				1: One shot processing only --------.
	 *				Gp: Generate secret pair --------.  |
	 *				Ge: Generate secret value ----.  |  |
	 *				Wr|Uw: Wrap/Unwrap -------.   |  |  |
	 *				Dr: Derive ----------.    |   |  |  |
	 *		Sr|Vr: SignRecover/VerifyRecov --.   |    |   |  |  |
	 *		Si|Ve: Sign/Verify --------.     |   |    |   |  |  |
	 *		En|De: Encrypt/Decrypt     |     |   |    |   |  |  |
	 *		Di: Digest -----.    |     |     |   |    |   |  |  |
	 *				|   / \   / \   / \  |   / \  |  |  |
	 * Mechanism			Di|En|De|Si|Ve|Sr|Vr|Dr|Wr|Uw|Ge|Gp|1
	 */
	SKS_M(AES_ECB,			0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0),
	SKS_M(AES_CBC,			0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0),
	SKS_M(AES_CBC_PAD,		0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0),
	SKS_M(AES_CTS,			0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
	SKS_M(AES_CTR,			0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
	SKS_M(AES_GCM,			0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
	SKS_M(AES_CCM,			0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
	SKS_M(AES_GMAC,			0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0),
	SKS_M(AES_CMAC,			0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(AES_CMAC_GENERAL,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(AES_ECB_ENCRYPT_DATA,	0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
	SKS_M(AES_CBC_ENCRYPT_DATA,	0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
	SKS_M(AES_KEY_GEN,		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
	/* Mechanism			Di|En|De|Si|Ve|Sr|Vr|Dr|Wr|Uw|Ge|Gp|1 */
	SKS_M(GENERIC_SECRET_KEY_GEN,	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
	SKS_M(MD5_HMAC,			0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA_1_HMAC,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA224_HMAC,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA256_HMAC,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA384_HMAC,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA512_HMAC,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(AES_XCBC_MAC,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	/* Mechanism			Di|En|De|Si|Ve|Sr|Vr|Dr|Wr|Uw|Ge|Gp|1 */
	SKS_M(EC_KEY_PAIR_GEN,		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0),
	SKS_M(ECDSA,			0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1),
	SKS_M(ECDSA_SHA1,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(ECDSA_SHA224,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(ECDSA_SHA256,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(ECDSA_SHA384,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(ECDSA_SHA512,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(ECDH1_DERIVE,		0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
	SKS_M(ECDH1_COFACTOR_DERIVE,	0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
	SKS_M(ECMQV_DERIVE,		0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
	SKS_M(ECDH_AES_KEY_WRAP,	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
	/* Mechanism			Di|En|De|Si|Ve|Sr|Vr|Dr|Wr|Uw|Ge|Gp|1 */
	SKS_M(RSA_PKCS_KEY_PAIR_GEN,	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0),
	SKS_M(RSA_PKCS,			0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1),
	SKS_M(RSA_PKCS_PSS,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1),
	SKS_M(RSA_PKCS_OAEP,		0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1),
	SKS_M(RSA_9796,			0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1),
	SKS_M(RSA_X_509,		0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1),
	SKS_M(SHA1_RSA_PKCS,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0),
	SKS_M(SHA1_RSA_PKCS_PSS,	0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA256_RSA_PKCS,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA384_RSA_PKCS,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA512_RSA_PKCS,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA256_RSA_PKCS_PSS,	0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA384_RSA_PKCS_PSS,	0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA512_RSA_PKCS_PSS,	0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA224_RSA_PKCS,		0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA224_RSA_PKCS_PSS,	0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(RSA_AES_KEY_WRAP,		0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0),
	/* Mechanism			Di|En|De|Si|Ve|Sr|Vr|Dr|Wr|Uw|Ge|Gp|1 */
	SKS_M(MD5,			1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA_1,			1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA224,			1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA256,			1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA384,			1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	SKS_M(SHA512,			1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	/*
	 * Mechanism			Di|En|De|Si|Ve|Sr|Vr|Dr|Wr|Uw|Ge|Gp|1
	 *                              |   \_/   \_/   \_/  |   \_/  |  |  |
	 *		Di: Digest -----'    |     |     |   |    |   |  |  |
	 *		En|De: Encrypt/Decrypt     |     |   |    |   |  |  |
	 *		Si|Ve: Sign/Verify --------'     |   |    |   |  |  |
	 *		Sr|Vr: SignUpdate/VerifyRecover -'   |    |   |  |  |
	 *				Dr: Derive ----------'    |   |  |  |
	 *				Wr|Uw: Wrap/Unwrap -------'   |  |  |
	 *				Ge: Generate secret value ----'  |  |
	 *				Gp: Generate secret pair --------'  |
	 *				1: One shot processing only --------'
	 */
};

static uint32_t sks_function2ckfm(enum processing_func function)
{
	switch (function) {
	case SKS_FUNCTION_DIGEST:
		return SKS_CKFM_DIGEST;
	case SKS_FUNCTION_GENERATE:
		return SKS_CKFM_GENERATE;
	case SKS_FUNCTION_GENERATE_PAIR:
		return SKS_CKFM_GENERATE_PAIR;
	case SKS_FUNCTION_DERIVE:
		return SKS_CKFM_DERIVE;
	case SKS_FUNCTION_WRAP:
		return SKS_CKFM_WRAP;
	case SKS_FUNCTION_UNWRAP:
		return SKS_CKFM_UNWRAP;
	case SKS_FUNCTION_ENCRYPT:
		return SKS_CKFM_ENCRYPT;
	case SKS_FUNCTION_DECRYPT:
		return SKS_CKFM_DECRYPT;
	case SKS_FUNCTION_SIGN:
		return SKS_CKFM_SIGN;
	case SKS_FUNCTION_VERIFY:
		return SKS_CKFM_VERIFY;
	case SKS_FUNCTION_SIGN_RECOVER:
		return SKS_CKFM_SIGN_RECOVER;
	case SKS_FUNCTION_VERIFY_RECOVER:
		return SKS_CKFM_VERIFY_RECOVER;
	default:
		return 0;
	}
}

int check_pkcs11_mechanism_flags(uint32_t mechanism_type, uint32_t flags)
{
	size_t n;
	uint32_t test_flags = flags & (SKS_CKFM_ENCRYPT | SKS_CKFM_DECRYPT |
				SKS_CKFM_DERIVE | SKS_CKFM_DIGEST |
				SKS_CKFM_SIGN | SKS_CKFM_SIGN_RECOVER |
				SKS_CKFM_VERIFY | SKS_CKFM_VERIFY_RECOVER |
				SKS_CKFM_GENERATE | SKS_CKFM_GENERATE_PAIR |
				SKS_CKFM_WRAP | SKS_CKFM_UNWRAP);

	for (n = 0; n < ARRAY_SIZE(pkcs11_modes); n++) {
		if (pkcs11_modes[n].id == mechanism_type) {
			if (test_flags & ~pkcs11_modes[n].flags) {
				EMSG("%s flags: 0x%" PRIx32 " vs 0x%" PRIx32,
					sks2str_proc(mechanism_type),
					test_flags, pkcs11_modes[n].flags);
			}
			return test_flags & ~pkcs11_modes[n].flags;
		}
	}

	return 1;
}

uint32_t check_mechanism_against_processing(struct pkcs11_session *session,
					    uint32_t mechanism_type,
					    enum processing_func function,
					    enum processing_step step)
{
	size_t n;
	bool allowed = false;


	switch (step) {
	case SKS_FUNC_STEP_INIT:
		switch (function) {
		case SKS_FUNCTION_IMPORT:
		case SKS_FUNCTION_COPY:
		case SKS_FUNCTION_MODIFY:
		case SKS_FUNCTION_DESTROY:
			return SKS_OK;
		default:
			for (n = 0; n < ARRAY_SIZE(pkcs11_modes); n++) {
				if (pkcs11_modes[n].id == mechanism_type) {
					allowed = pkcs11_modes[n].flags &
						  sks_function2ckfm(function);
					break;
				}
			}
			break;
		}
		break;

	case SKS_FUNC_STEP_ONESHOT:
	case SKS_FUNC_STEP_UPDATE:
		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return SKS_CKR_USER_NOT_LOGGED_IN;

		if (!session->processing->updated) {
			allowed = true;
		} else {
			for (n = 0; n < ARRAY_SIZE(pkcs11_modes); n++) {
				if (pkcs11_modes[n].id == mechanism_type) {
					allowed = !pkcs11_modes[n].one_shot;
					break;
				}
			}
		}
		break;

	case SKS_FUNC_STEP_FINAL:
		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return SKS_CKR_USER_NOT_LOGGED_IN;

		return SKS_OK;

	default:
		TEE_Panic(step);
		break;
	}

	if (!allowed)
		EMSG("Processing %s (%" PRIx32 ") not permitted (%u/%u)",
			sks2str_proc(mechanism_type), mechanism_type,
			function, step);

	return allowed ? SKS_OK : SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
}

/*
 * Object default boolean attributes as per PKCS#11
 */
static uint8_t *pkcs11_object_default_boolprop(uint32_t attribute)
{
	static const uint8_t bool_true = 1;
	static const uint8_t bool_false = 0;

	switch (attribute) {
	/* As per PKCS#11 default value */
	case SKS_CKA_MODIFIABLE:
	case SKS_CKA_COPYABLE:
	case SKS_CKA_DESTROYABLE:
		return (uint8_t *)&bool_true;
	case SKS_CKA_TOKEN:
	case SKS_CKA_PRIVATE:
	case SKS_CKA_SENSITIVE:  /* TODO: symkey false, privkey: token specific */
	/* Token specific default value */
	case SKS_CKA_DERIVE:
	case SKS_CKA_ENCRYPT:
	case SKS_CKA_DECRYPT:
	case SKS_CKA_SIGN:
	case SKS_CKA_VERIFY:
	case SKS_CKA_SIGN_RECOVER:
	case SKS_CKA_VERIFY_RECOVER:
	case SKS_CKA_WRAP:
	case SKS_CKA_UNWRAP:
	case SKS_CKA_EXTRACTABLE:
	case SKS_CKA_WRAP_WITH_TRUSTED:
	case SKS_CKA_ALWAYS_AUTHENTICATE:
	case SKS_CKA_TRUSTED:
		return (uint8_t *)&bool_false;
	default:
		DMSG("No default for boolprop attribute 0x%" PRIx32, attribute);
		TEE_Panic(0); // FIXME: errno
	}

	/* Keep compiler happy */
	return NULL;
}

/*
 * Object expects several boolean attributes to be set to a default value
 * or to a validate client configuration value. This function append the input
 * attrubute (id/size/value) in the serailzed object.
 */
static uint32_t pkcs11_import_object_boolprop(struct sks_attrs_head **out,
					      struct sks_attrs_head *template,
					      uint32_t attribute)
{
	uint32_t rv;
	uint8_t bbool;
	size_t size = sizeof(uint8_t);
	void *attr;

	rv = get_attribute(template, attribute, &bbool, &size);
	if (rv || !bbool)
		attr = pkcs11_object_default_boolprop(attribute);
	else
		attr = &bbool;

	/* Boolean attributes are 1byte in the ABI, no alignment issue */
	return add_attribute(out, attribute, attr, sizeof(uint8_t));
}

static uint32_t set_mandatory_boolprops(struct sks_attrs_head **out,
					struct sks_attrs_head *temp,
					uint32_t const *bp, size_t bp_count)
{
	uint32_t rv = SKS_OK;
	size_t n;

	for (n = 0; n < bp_count; n++) {
		rv = pkcs11_import_object_boolprop(out, temp, bp[n]);
		if (rv)
			return rv;
	}

	return rv;
}

static uint32_t __unused set_mandatory_attributes(struct sks_attrs_head **out,
					 struct sks_attrs_head *temp,
					 uint32_t const *bp, size_t bp_count)
{
	uint32_t rv = SKS_OK;
	size_t n;

	for (n = 0; n < bp_count; n++) {
		size_t size;
		void *value;

		if (get_attribute_ptr(temp, bp[n], &value, &size)) {
			/* FIXME: currently set attribute as empty. Fail? */
			size = 0;
		}

		rv = add_attribute(out, bp[n], value, size);
		if (rv)
			return rv;
	}

	return rv;
}

static uint32_t set_optional_attributes(struct sks_attrs_head **out,
					struct sks_attrs_head *temp,
					uint32_t const *bp, size_t bp_count)
{
	uint32_t rv = SKS_OK;
	size_t n;

	for (n = 0; n < bp_count; n++) {
		size_t size;
		void *value;

		if (get_attribute_ptr(temp, bp[n], &value, &size))
			continue;

		rv = add_attribute(out, bp[n], value, size);
		if (rv)
			return rv;
	}

	return rv;
}

/*
 * Below are listed the mandated or optional epected attributes for
 * PKCS#11 storage objects.
 *
 * Note: boolprops (manadated boolean attributes) SKS_CKA_ALWAYS_SENSITIVE,
 * and SKS_CKA_NEVER_EXTRACTABLE are set by the token, not provided
 * in the client template.
 */

/* PKCS#11 specification for any object (session/token) of the storage */
static const uint32_t pkcs11_any_object_boolprops[] = {
	SKS_CKA_TOKEN, SKS_CKA_PRIVATE,
	SKS_CKA_MODIFIABLE, SKS_CKA_COPYABLE, SKS_CKA_DESTROYABLE,
};
static const uint32_t pkcs11_any_object_optional[] = {
	SKS_CKA_LABEL,
};
/* PKCS#11 specification for raw data object (+pkcs11_any_object_xxx) */
const uint32_t pkcs11_raw_data_optional[] = {
	SKS_CKA_OBJECT_ID, SKS_CKA_APPLICATION, SKS_CKA_VALUE,
};
/* PKCS#11 specification for any key object (+pkcs11_any_object_xxx) */
static const uint32_t pkcs11_any_key_boolprops[] = {
	SKS_CKA_DERIVE,
};
static const uint32_t pkcs11_any_key_optional[] = {
	SKS_CKA_ID,
	SKS_CKA_START_DATE, SKS_CKA_END_DATE,
	SKS_CKA_ALLOWED_MECHANISMS,
};
/* PKCS#11 specification for any symmetric key (+pkcs11_any_key_xxx) */
static const uint32_t pkcs11_symm_key_boolprops[] = {
	SKS_CKA_ENCRYPT, SKS_CKA_DECRYPT, SKS_CKA_SIGN, SKS_CKA_VERIFY,
	SKS_CKA_WRAP, SKS_CKA_UNWRAP,
	SKS_CKA_SENSITIVE, SKS_CKA_EXTRACTABLE,
	SKS_CKA_WRAP_WITH_TRUSTED, SKS_CKA_TRUSTED,
};
static const uint32_t pkcs11_symm_key_optional[] = {
	SKS_CKA_WRAP_TEMPLATE, SKS_CKA_UNWRAP_TEMPLATE, SKS_CKA_DERIVE_TEMPLATE,
	SKS_CKA_VALUE, SKS_CKA_VALUE_LEN,
};
/* PKCS#11 specification for any asymmetric public key (+pkcs11_any_key_xxx) */
static const uint32_t pkcs11_public_key_boolprops[] = {
	SKS_CKA_ENCRYPT, SKS_CKA_VERIFY, SKS_CKA_VERIFY_RECOVER, SKS_CKA_WRAP,
	SKS_CKA_TRUSTED,
};
static const uint32_t pkcs11_public_key_mandated[] = {
	SKS_CKA_SUBJECT
};
static const uint32_t pkcs11_public_key_optional[] = {
	SKS_CKA_WRAP_TEMPLATE, SKS_CKA_PUBLIC_KEY_INFO,
};
/* PKCS#11 specification for any asymmetric private key (+pkcs11_any_key_xxx) */
static const uint32_t pkcs11_private_key_boolprops[] = {
	SKS_CKA_DECRYPT, SKS_CKA_SIGN, SKS_CKA_SIGN_RECOVER,
	SKS_CKA_UNWRAP,
	SKS_CKA_SENSITIVE, SKS_CKA_EXTRACTABLE,
	SKS_CKA_WRAP_WITH_TRUSTED, SKS_CKA_ALWAYS_AUTHENTICATE,
};
static const uint32_t pkcs11_private_key_mandated[] = {
	SKS_CKA_SUBJECT
};
static const uint32_t pkcs11_private_key_optional[] = {
	SKS_CKA_UNWRAP_TEMPLATE, SKS_CKA_PUBLIC_KEY_INFO,
};
/* PKCS#11 specification for any RSA key (+pkcs11_public/private_key_xxx) */
static const uint32_t pkcs11_rsa_public_key_mandated[] = {
	SKS_CKA_MODULUS_BITS,
};
static const uint32_t pkcs11_rsa_public_key_optional[] = {
	SKS_CKA_MODULUS, SKS_CKA_PUBLIC_EXPONENT,
};
static const uint32_t pkcs11_rsa_private_key_optional[] = {
	SKS_CKA_MODULUS, SKS_CKA_PUBLIC_EXPONENT, SKS_CKA_PRIVATE_EXPONENT,
	SKS_CKA_PRIME_1, SKS_CKA_PRIME_2,
	SKS_CKA_EXPONENT_1, SKS_CKA_EXPONENT_2,	SKS_CKA_COEFFICIENT,
};
/* PKCS#11 specification for any EC key (+pkcs11_public/private_key_xxx) */
static const uint32_t pkcs11_ec_public_key_mandated[] = {
	SKS_CKA_EC_PARAMS,
};
static const uint32_t pkcs11_ec_public_key_optional[] = {
	SKS_CKA_EC_POINT,
	SKS_CKA_EC_POINT_X, SKS_CKA_EC_POINT_Y, // temporaary until DER support
};
static const uint32_t pkcs11_ec_private_key_mandated[] = {
	SKS_CKA_EC_PARAMS,
};
static const uint32_t pkcs11_ec_private_key_optional[] = {
	SKS_CKA_VALUE,
	SKS_CKA_EC_POINT_X, SKS_CKA_EC_POINT_Y, // temporaary until DER support
};

static uint32_t create_pkcs11_storage_attributes(struct sks_attrs_head **out,
						 struct sks_attrs_head *temp)
{
	uint32_t const *boolprops = &pkcs11_any_object_boolprops[0];
	uint32_t const *optional = &pkcs11_any_object_optional[0];
	size_t boolprops_count = ARRAY_SIZE(pkcs11_any_object_boolprops);
	size_t optional_count = ARRAY_SIZE(pkcs11_any_object_optional);
	uint32_t class;
	uint32_t rv;

	init_attributes_head(out);
#ifdef SKS_SHEAD_WITH_BOOLPROPS
	set_attributes_in_head(*out);
#endif

	/* Object class is mandatory */
	class = get_class(temp);
	if (class == SKS_UNDEFINED_ID) {
		EMSG("Class attribute not found");
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}
	rv = add_attribute(out, SKS_CKA_CLASS, &class, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = set_mandatory_boolprops(out, temp, boolprops, boolprops_count);
	if (rv)
		return rv;

	return set_optional_attributes(out, temp, optional, optional_count);
}

static uint32_t create_pkcs11_genkey_attributes(struct sks_attrs_head **out,
						struct sks_attrs_head *temp)
{
	uint32_t const *boolprops = &pkcs11_any_key_boolprops[0];
	uint32_t const *optional = &pkcs11_any_key_optional[0];
	size_t boolprops_count = ARRAY_SIZE(pkcs11_any_key_boolprops);
	size_t optional_count = ARRAY_SIZE(pkcs11_any_key_optional);
	uint32_t type;
	uint32_t rv;

	rv = create_pkcs11_storage_attributes(out, temp);
	if (rv)
		return rv;

	type = get_type(temp);
	if (type == SKS_UNDEFINED_ID) {
		EMSG("Key type attribute not found");
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}
	rv = add_attribute(out, SKS_CKA_KEY_TYPE, &type, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = set_mandatory_boolprops(out, temp, boolprops, boolprops_count);
	if (rv)
		return rv;

	return set_optional_attributes(out, temp, optional, optional_count);
}

static uint32_t create_pkcs11_symm_key_attributes(struct sks_attrs_head **out,
						  struct sks_attrs_head *temp)
{
	uint32_t const *boolprops = &pkcs11_symm_key_boolprops[0];
	uint32_t const *optional = &pkcs11_symm_key_optional[0];
	size_t boolprops_count = ARRAY_SIZE(pkcs11_symm_key_boolprops);
	size_t optional_count = ARRAY_SIZE(pkcs11_symm_key_optional);
	uint32_t rv;

	assert(get_class(temp) == SKS_CKO_SECRET_KEY);

	rv = create_pkcs11_genkey_attributes(out, temp);
	if (rv)
		return rv;

	assert(get_class(*out) == SKS_CKO_SECRET_KEY);

	switch (get_type(*out)) {
	case SKS_CKK_GENERIC_SECRET:
	case SKS_CKK_AES:
	case SKS_CKK_MD5_HMAC:
	case SKS_CKK_SHA_1_HMAC:
	case SKS_CKK_SHA256_HMAC:
	case SKS_CKK_SHA384_HMAC:
	case SKS_CKK_SHA512_HMAC:
	case SKS_CKK_SHA224_HMAC:
		break;
	default:
		EMSG("Invalid key type (0x%" PRIx32 ", %s)",
			get_type(*out), sks2str_key_type(get_type(*out)));
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}

	rv = set_mandatory_boolprops(out, temp, boolprops, boolprops_count);
	if (rv)
		return rv;

	return set_optional_attributes(out, temp, optional, optional_count);
}

static uint32_t create_pkcs11_data_attributes(struct sks_attrs_head **out,
					      struct sks_attrs_head *temp)
{
	uint32_t rv;

	assert(get_class(temp) == SKS_CKO_DATA);

	rv = create_pkcs11_storage_attributes(out, temp);
	if (rv)
		return rv;

	assert(get_class(*out) == SKS_CKO_DATA);

	rv = set_optional_attributes(out, temp,
				     &pkcs11_raw_data_optional[0],
				     ARRAY_SIZE(pkcs11_raw_data_optional));

	return rv;
}

static uint32_t create_pkcs11_pub_key_attributes(struct sks_attrs_head **out,
						 struct sks_attrs_head *temp)
{
	uint32_t rv;
	uint32_t const *boolprops = &pkcs11_public_key_boolprops[0];
	uint32_t const *mandated = &pkcs11_public_key_mandated[0];
	uint32_t const *optional = &pkcs11_public_key_optional[0];
	size_t boolprops_count = ARRAY_SIZE(pkcs11_public_key_boolprops);
	size_t mandated_count = ARRAY_SIZE(pkcs11_public_key_mandated);
	size_t optional_count = ARRAY_SIZE(pkcs11_public_key_optional);

	assert(get_class(temp) == SKS_CKO_PUBLIC_KEY);

	rv = create_pkcs11_genkey_attributes(out, temp);
	if (rv)
		return rv;

	assert(get_class(*out) == SKS_CKO_PUBLIC_KEY);

	rv = set_mandatory_boolprops(out, temp, boolprops, boolprops_count);
	if (rv)
		return rv;

	rv = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rv)
		return rv;

	rv = set_optional_attributes(out, temp, optional, optional_count);
	if (rv)
		return rv;

	switch (get_type(*out)) {
	case SKS_CKK_RSA:
		boolprops = NULL;
		mandated = &pkcs11_rsa_public_key_mandated[0];
		optional = &pkcs11_rsa_public_key_optional[0];
		boolprops_count = 0;
		mandated_count = ARRAY_SIZE(pkcs11_rsa_public_key_mandated);
		optional_count = ARRAY_SIZE(pkcs11_rsa_public_key_optional);
		break;
	case SKS_CKK_EC:
		boolprops = NULL;
		mandated = &pkcs11_ec_public_key_mandated[0];
		optional = &pkcs11_ec_public_key_optional[0];
		boolprops_count = 0;
		mandated_count = ARRAY_SIZE(pkcs11_ec_public_key_mandated);
		optional_count = ARRAY_SIZE(pkcs11_ec_public_key_optional);
		break;
	default:
		EMSG("Invalid key type (0x%" PRIx32 ", %s)",
			get_type(*out), sks2str_key_type(get_type(*out)));
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}

	rv = set_mandatory_boolprops(out, temp, boolprops, boolprops_count);
	if (rv)
		return rv;

	rv = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rv)
		return rv;

	return set_optional_attributes(out, temp, optional, optional_count);
}

static uint32_t create_pkcs11_priv_key_attributes(struct sks_attrs_head **out,
						  struct sks_attrs_head *temp)
{
	uint32_t const *boolprops = &pkcs11_private_key_boolprops[0];
	uint32_t const *mandated = &pkcs11_private_key_mandated[0];
	uint32_t const *optional = &pkcs11_private_key_optional[0];
	size_t boolprops_count = ARRAY_SIZE(pkcs11_private_key_boolprops);
	size_t mandated_count = ARRAY_SIZE(pkcs11_private_key_mandated);
	size_t optional_count = ARRAY_SIZE(pkcs11_private_key_optional);
	uint32_t rv;

	assert(get_class(temp) == SKS_CKO_PRIVATE_KEY);

	rv = create_pkcs11_genkey_attributes(out, temp);
	if (rv)
		return rv;

	assert(get_class(*out) == SKS_CKO_PRIVATE_KEY);

	rv = set_mandatory_boolprops(out, temp, boolprops, boolprops_count);
	if (rv)
		return rv;

	rv = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rv)
		return rv;

	rv = set_optional_attributes(out, temp, optional, optional_count);
	if (rv)
		return rv;

	switch (get_type(*out)) {
	case SKS_CKK_RSA:
		boolprops = NULL;
		mandated = NULL;
		optional = &pkcs11_rsa_private_key_optional[0];
		boolprops_count = 0;
		mandated_count = 0;
		optional_count = ARRAY_SIZE(pkcs11_rsa_private_key_optional);
		break;
	case SKS_CKK_EC:
		boolprops = NULL;
		mandated = &pkcs11_ec_private_key_mandated[0];
		optional = &pkcs11_ec_private_key_optional[0];
		boolprops_count = 0;
		mandated_count = ARRAY_SIZE(pkcs11_ec_private_key_mandated);
		optional_count = ARRAY_SIZE(pkcs11_ec_private_key_optional);
		break;
	default:
		EMSG("Invalid key type (0x%" PRIx32 ", %s)",
			get_type(*out), sks2str_key_type(get_type(*out)));
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}

	rv = set_mandatory_boolprops(out, temp, boolprops, boolprops_count);
	if (rv)
		return rv;

	rv = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rv)
		return rv;

	return set_optional_attributes(out, temp, optional, optional_count);
}

/*
 * Create an attribute list for a new object from a template and a parent
 * object (optional) for an object generation function (generate, copy,
 * derive...).
 *
 * PKCS#11 directves on the supplied template:
 * - template has aninvalid attribute ID: return ATTRIBUTE_TYPE_INVALID
 * - template has an invalid value for an attribute: return ATTRIBUTE_VALID_INVALID
 * - template has value for a read-only attribute: retrun ATTRIBUTE_READ_ONLY
 * - template+default+parent => still miss an attribute: return TEMPLATE_INCONSISTENT
 *
 * INFO on SKS_CMD_COPY_OBJECT:
 * - parent SKS_CKA_COPYIABLE=false => return ACTION_PROHIBITED.
 * - template can specify SKS_CKA_TOKEN, SKS_CKA_PRIVATE, SKS_CKA_MODIFIABLE,
 *   SKS_CKA_DESTROYABLE.
 * - SENSITIVE can change from flase to true, not from true to false.
 * - LOCAL is the parent LOCAL
 */
uint32_t create_attributes_from_template(struct sks_attrs_head **out,
					 void *template, size_t template_size,
					 struct sks_attrs_head *parent,
					 enum processing_func function)
{
	struct sks_attrs_head *temp = NULL;
	struct sks_attrs_head *attrs = NULL;
	uint32_t rv;
	uint8_t local;
	uint8_t always_sensitive;
	uint8_t never_extract;

#ifdef DEBUG	/* Sanity: check function argument */
	trace_attributes_from_api_head("template", template, template_size);
	switch (function) {
	case SKS_FUNCTION_GENERATE:
	case SKS_FUNCTION_GENERATE_PAIR:
	case SKS_FUNCTION_IMPORT:
		break;
	case SKS_FUNCTION_DERIVE:
		trace_attributes("parent", parent);
		break;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
#endif

	rv = sanitize_client_object(&temp, template, template_size);
	if (rv)
		goto bail;

	if (!sanitize_consistent_class_and_type(temp)) {
		EMSG("inconsistent class/type");
		rv = SKS_CKR_TEMPLATE_INCONSISTENT;
		goto bail;
	}

	switch (get_class(temp)) {
	case SKS_CKO_DATA:
		rv = create_pkcs11_data_attributes(&attrs, temp);
		break;
	case SKS_CKO_SECRET_KEY:
		rv = create_pkcs11_symm_key_attributes(&attrs, temp);
		break;
	case SKS_CKO_PUBLIC_KEY:
		rv = create_pkcs11_pub_key_attributes(&attrs, temp);
		break;
	case SKS_CKO_PRIVATE_KEY:
		rv = create_pkcs11_priv_key_attributes(&attrs, temp);
		break;
	default:
		DMSG("Invalid object class 0x%" PRIx32 "/%s",
			get_class(temp), sks2str_class(get_class(temp)));
		rv = SKS_CKR_TEMPLATE_INCONSISTENT;
		break;
	}
	if (rv)
		goto bail;

	assert(get_attribute(attrs, SKS_CKA_LOCAL, NULL, NULL) ==
		SKS_NOT_FOUND);

	switch (function) {
	case SKS_FUNCTION_GENERATE:
	case SKS_FUNCTION_GENERATE_PAIR:
		local = SKS_TRUE;
		break;
	case SKS_FUNCTION_COPY:
		local = get_bool(parent, SKS_CKA_LOCAL);
		break;
	case SKS_FUNCTION_DERIVE:
	default:
		local = SKS_FALSE;
		break;
	}
	rv = add_attribute(&attrs, SKS_CKA_LOCAL, &local, sizeof(local));
	if (rv)
		goto bail;

	switch (get_class(attrs)) {
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PRIVATE_KEY:
	case SKS_CKO_PUBLIC_KEY:
		always_sensitive = SKS_FALSE;
		never_extract = SKS_FALSE;

		switch (function) {
		case SKS_FUNCTION_DERIVE:
		case SKS_FUNCTION_COPY:
			always_sensitive =
				get_bool(parent, SKS_CKA_ALWAYS_SENSITIVE) &&
				get_bool(attrs, SKS_CKA_SENSITIVE);
			never_extract =
				get_bool(parent, SKS_CKA_NEVER_EXTRACTABLE) &&
				!get_bool(attrs, SKS_CKA_EXTRACTABLE);
			break;
		case SKS_FUNCTION_GENERATE:
			always_sensitive = get_bool(attrs, SKS_CKA_SENSITIVE);
			never_extract = !get_bool(attrs, SKS_CKA_EXTRACTABLE);
			break;
		default:
			break;
		}

		rv = add_attribute(&attrs, SKS_CKA_ALWAYS_SENSITIVE,
				   &always_sensitive, sizeof(always_sensitive));
		if (rv)
			goto bail;

		rv = add_attribute(&attrs, SKS_CKA_NEVER_EXTRACTABLE,
				   &never_extract, sizeof(never_extract));
		if (rv)
			goto bail;

		break;

	default:
		break;
	}

	*out = attrs;

#ifdef DEBUG
	trace_attributes("object", attrs);
#endif

bail:
	TEE_Free(temp);
	if (rv)
		TEE_Free(attrs);

	return rv;
}

static uint32_t check_attrs_misc_integrity(struct sks_attrs_head *head)
{
	/* FIXME: is it useful? */
	if (get_bool(head, SKS_CKA_NEVER_EXTRACTABLE) &&
	    get_bool(head, SKS_CKA_EXTRACTABLE)) {
		DMSG("Never/Extractable attributes mismatch %d/%d",
			get_bool(head, SKS_CKA_NEVER_EXTRACTABLE),
			get_bool(head, SKS_CKA_EXTRACTABLE));
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}

	if (get_bool(head, SKS_CKA_ALWAYS_SENSITIVE) &&
	    !get_bool(head, SKS_CKA_SENSITIVE)) {
		DMSG("Sensitive/always attributes mismatch %d/%d",
			get_bool(head, SKS_CKA_SENSITIVE),
			get_bool(head, SKS_CKA_ALWAYS_SENSITIVE));
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}

	return SKS_OK;
}

/*
 * Check access to object against authentication to token
 */
uint32_t check_access_attrs_against_token(struct pkcs11_session *session,
					  struct sks_attrs_head *head)
{
	bool private = true;

	switch(get_class(head)) {
	case SKS_CKO_SECRET_KEY:
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_DATA:
		if (!get_bool(head, SKS_CKA_PRIVATE))
			private = false;
		break;
	case SKS_CKO_PRIVATE_KEY:
		break;
	default:
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	if (private && pkcs11_session_is_public(session)) {
		DMSG("Private object access from a public session");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	/*
	 * TODO: START_DATE and END_DATE: complies with current time?
	 */
	return SKS_OK;
}

/*
 * Check the attributes of a to-be-created object matches the token state
 */
uint32_t check_created_attrs_against_token(struct pkcs11_session *session,
					   struct sks_attrs_head *head)
{
	uint32_t rc;

	rc = check_attrs_misc_integrity(head);
	if (rc)
		return rc;

	if (get_bool(head, SKS_CKA_TRUSTED) &&
	    !pkcs11_session_is_security_officer(session)) {
		DMSG("Can't create trusted object");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	if (get_bool(head, SKS_CKA_TOKEN) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't create persistent object");
		return SKS_CKR_SESSION_READ_ONLY;
	}

	/*
	 * TODO: START_DATE and END_DATE: complies with current time?
	 */
	return SKS_OK;
}

/*
 * Check the attributes of new secret match the requirements of the parent key.
 */
uint32_t check_created_attrs_against_parent_key(
					uint32_t proc_id __unused,
					struct sks_attrs_head *parent __unused,
					struct sks_attrs_head *head __unused)
{
	/*
	 * TODO
	 * Depends on the processing§/mechanism used.
	 * Wrapping: check head vs parent key WRAP_TEMPLATE attribute.
	 * Unwrapping: check head vs parent key UNWRAP_TEMPLATE attribute.
	 * Derive: check head vs parent key DERIVE_TEMPLATE attribute (late comer?).
	 */
	return SKS_ERROR;
}

#define DMSG_BAD_BBOOL(attr, proc, head) \
	do {	\
		uint8_t bvalue __maybe_unused;			\
								\
		DMSG("%s issue for %s: %sfound, value %d",	\
			sks2str_attr(attr),			\
			sks2str_proc(proc),			\
			get_attribute(head, attr, &bvalue, NULL) ? \
			"not " : "",				\
			bvalue);				\
	} while (0)

/*
 * Check the attributes of a new secret match the processing/mechanism
 * used to create it.
 *
 * @proc_id - SKS_CKM__xxx
 * @subproc_id - boolean attribute id as encrypt/decrypt/sign/verify,
 *		 if applicable to proc_id.
 * @head - head of the attributes of the to-be-created object.
 */
uint32_t check_created_attrs_against_processing(uint32_t proc_id,
						struct sks_attrs_head *head)
{
	uint8_t bbool;

	/*
	 * Processings that do not create secrets are not expected to call
	 * this function which would panic.
	 */
	/*
	 * FIXME: rellay need to check LOCAL here, it was safely set from
	 * create_attributes_from_template().
	 */
	switch (proc_id) {
	case SKS_PROCESSING_IMPORT:
	case SKS_CKM_ECDH1_DERIVE:
	case SKS_CKM_ECDH1_COFACTOR_DERIVE:
	case SKS_CKM_DH_PKCS_DERIVE:
		if (get_attribute(head, SKS_CKA_LOCAL, &bbool, NULL) ||
		    bbool) {
			DMSG_BAD_BBOOL(SKS_CKA_LOCAL, proc_id, head);
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		}
		break;
	case SKS_CKM_GENERIC_SECRET_KEY_GEN:
	case SKS_CKM_AES_KEY_GEN:
	case SKS_CKM_EC_KEY_PAIR_GEN:
	case SKS_CKM_RSA_PKCS_KEY_PAIR_GEN:
		if (get_attribute(head, SKS_CKA_LOCAL, &bbool, NULL) ||
		    !bbool) {
			DMSG_BAD_BBOOL(SKS_CKA_LOCAL, proc_id, head);
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		}
		break;
	default:
		TEE_Panic(proc_id);
		break;
	}

	switch (proc_id) {
	case SKS_CKM_GENERIC_SECRET_KEY_GEN:
		if (get_type(head) != SKS_CKK_GENERIC_SECRET)
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		break;
	case SKS_CKM_AES_KEY_GEN:
		if (get_type(head) != SKS_CKK_AES)
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		break;
	case SKS_CKM_EC_KEY_PAIR_GEN:
		if (get_type(head) != SKS_CKK_EC)
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		break;
	case SKS_CKM_RSA_PKCS_KEY_PAIR_GEN:
		if (get_type(head) != SKS_CKK_RSA)
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		break;
	case SKS_CKM_ECDH1_DERIVE:
	case SKS_CKM_ECDH1_COFACTOR_DERIVE:
	case SKS_CKM_DH_PKCS_DERIVE:
		if (get_class(head) != SKS_CKO_SECRET_KEY)
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		break;
	case SKS_PROCESSING_IMPORT:
	default:
		break;
	}

	return SKS_OK;
}

void pkcs11_max_min_key_size(uint32_t key_type, uint32_t *max_key_size,
			     uint32_t *min_key_size, bool bit_size_only)
{
	uint32_t mult = bit_size_only ? 8 : 1;

	switch (key_type) {
	case SKS_CKK_GENERIC_SECRET:
		*min_key_size = 1;	/* in bits */
		*max_key_size = 4096;	/* in bits */
		break;
	case SKS_CKK_MD5_HMAC:
		*min_key_size = 16 * mult;
		*max_key_size = 16 * mult;
		break;
	case SKS_CKK_SHA_1_HMAC:
		*min_key_size = 20 * mult;
		*max_key_size = 20 * mult;
		break;
	case SKS_CKK_SHA224_HMAC:
		*min_key_size = 28 * mult;
		*max_key_size = 28 * mult;
		break;
	case SKS_CKK_SHA256_HMAC:
		*min_key_size = 32 * mult;
		*max_key_size = 32 * mult;
		break;
	case SKS_CKK_SHA384_HMAC:
		*min_key_size = 48 * mult;
		*max_key_size = 48 * mult;
		break;
	case SKS_CKK_SHA512_HMAC:
		*min_key_size = 64 * mult;
		*max_key_size = 64 * mult;
		break;
	case SKS_CKK_AES:
		*min_key_size = 16 * mult;
		*max_key_size = 32 * mult;
		break;
	case SKS_CKK_EC:
		*min_key_size = 192;	/* in bits */
		*max_key_size = 521;	/* in bits */
		break;
	case SKS_CKK_RSA:
	case SKS_CKK_DSA:
	case SKS_CKK_DH:
		*min_key_size = 256;	/* in bits */
		*max_key_size = 4096;	/* in bits */
		break;
	default:
		TEE_Panic(key_type);
		break;
	}
}

uint32_t check_created_attrs(struct sks_attrs_head *key1,
			     struct sks_attrs_head *key2)
{
	struct sks_attrs_head *secret = NULL;
	struct sks_attrs_head *private = NULL;
	struct sks_attrs_head *public = NULL;
	uint32_t max_key_size;
	uint32_t min_key_size;
	uint32_t key_length = 0;
	uint32_t rv;

	switch (get_class(key1)) {
	case SKS_CKO_SECRET_KEY:
		secret = key1;
		break;
	case SKS_CKO_PUBLIC_KEY:
		public = key1;
		break;
	case SKS_CKO_PRIVATE_KEY:
		private = key1;
		break;
	default:
		return SKS_CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (key2) {
		switch (get_class(key2)) {
		case SKS_CKO_PUBLIC_KEY:
			public = key2;
			if (private == key1)
				break;

			return SKS_CKR_TEMPLATE_INCONSISTENT;
		case SKS_CKO_PRIVATE_KEY:
			private = key2;
			if (public == key1)
				break;

			return SKS_CKR_TEMPLATE_INCONSISTENT;
		default:
			return SKS_CKR_ATTRIBUTE_VALUE_INVALID;
		}

		if (get_type(private) != get_type(public))
			return SKS_CKR_TEMPLATE_INCONSISTENT;
	}

	if (secret) {
		switch (get_type(secret)) {
		case SKS_CKK_AES:
		case SKS_CKK_GENERIC_SECRET:
		case SKS_CKK_MD5_HMAC:
		case SKS_CKK_SHA_1_HMAC:
		case SKS_CKK_SHA224_HMAC:
		case SKS_CKK_SHA256_HMAC:
		case SKS_CKK_SHA384_HMAC:
		case SKS_CKK_SHA512_HMAC:
			break;
		default:
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		}

		/* Get key size */
		rv = get_u32_attribute(secret, SKS_CKA_VALUE_LEN, &key_length);
		if (rv)
			return rv;
	}
	if (public) {
		switch (get_type(public)) {
		case SKS_CKK_RSA:
		case SKS_CKK_DSA:
		case SKS_CKK_DH:
			/* Get key size */
			rv = get_u32_attribute(public, SKS_CKA_MODULUS_BITS,
						&key_length);
			if (rv)
				return rv;
			break;
		case SKS_CKK_EC:
			break;
		default:
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		}
	}
	if (private) {
		switch (get_type(private)) {
		case SKS_CKK_RSA:
		case SKS_CKK_DSA:
		case SKS_CKK_DH:
			/* Get key size, if key pair public carries bit size */
			if (public)
				break;

			rv = get_u32_attribute(private, SKS_CKA_MODULUS_BITS,
						&key_length);
			if (rv)
				return rv;
			break;
		case SKS_CKK_EC:
			/* No need to get key size */
			break;
		default:
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		}
	}

	/*
	 * Check key size for symmetric keys and RSA keys
	 * EC is bound to domains, no need to chekc here.
	 */
	switch (get_type(key1)) {
	case SKS_CKK_EC:
		return SKS_OK;
	default:
		break;
	}

	pkcs11_max_min_key_size(get_type(key1),
				&max_key_size, &min_key_size, false);

	if (key_length < min_key_size || key_length > max_key_size) {
		EMSG("Length %" PRIu32 " vs range [%" PRIu32 " %" PRIu32 "]",
			key_length, min_key_size, max_key_size);
		return SKS_CKR_KEY_SIZE_RANGE;
	}

	return SKS_OK;
}

/* Check processing ID against attributre ALLOWED_PROCESSINGS if any */
static bool parent_key_complies_allowed_processings(uint32_t proc_id,
						    struct sks_attrs_head *head)
{
	char *attr;
	size_t size;
	uint32_t proc;
	size_t count;

	/* Check only if restricted allowed mechanisms list is defined */
	if (get_attribute_ptr(head, SKS_CKA_ALLOWED_MECHANISMS,
			      (void *)&attr, &size) != SKS_OK) {
		return true;
	}

	for (count = size / sizeof(uint32_t); count; count--) {
		TEE_MemMove(&proc, attr, sizeof(uint32_t));
		attr += sizeof(uint32_t);

		if (proc == proc_id)
			return true;
	}

	DMSG("can't find %s in allowed list", sks2str_proc(proc_id));
	return false;
}

/*
 * Check the attributes of the parent secret (key) used in the processing
 * do match the target processing.
 *
 * @proc_id - SKS_CKM_xxx
 * @subproc_id - boolean attribute encrypt or decrypt or sign or verify, if
 *		 applicable to proc_id.
 * @head - head of the attributes of parent object.
 */
uint32_t check_parent_attrs_against_processing(uint32_t proc_id,
					       enum processing_func function,
					       struct sks_attrs_head *head)
{
	uint32_t rc __maybe_unused;
	uint32_t key_class = get_class(head);
	uint32_t key_type = get_type(head);

	if (function == SKS_FUNCTION_ENCRYPT &&
	    !get_bool(head, SKS_CKA_ENCRYPT)) {
		DMSG("encrypt not permitted");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if (function == SKS_FUNCTION_DECRYPT &&
	    !get_bool(head, SKS_CKA_DECRYPT)) {
		DMSG("decrypt not permitted");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if (function == SKS_FUNCTION_SIGN &&
	    !get_bool(head, SKS_CKA_SIGN)) {
		DMSG("sign not permitted");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if (function == SKS_FUNCTION_VERIFY &&
	    !get_bool(head, SKS_CKA_VERIFY)) {
		DMSG("verify not permitted");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if (function == SKS_FUNCTION_WRAP &&
	    !get_bool(head, SKS_CKA_WRAP)) {
		DMSG("wrap not permitted");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if (function == SKS_FUNCTION_UNWRAP &&
	    !get_bool(head, SKS_CKA_UNWRAP)) {
		DMSG("unwrap not permitted");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if (function == SKS_FUNCTION_DERIVE &&
	    !get_bool(head, SKS_CKA_DERIVE)) {
		DMSG("derive not permitted");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	/* Check processing complies for parent key family */
	switch (proc_id) {
	case SKS_CKM_AES_ECB:
	case SKS_CKM_AES_CBC:
	case SKS_CKM_AES_CBC_PAD:
	case SKS_CKM_AES_CTS:
	case SKS_CKM_AES_CTR:
	case SKS_CKM_AES_GCM:
	case SKS_CKM_AES_CCM:
	case SKS_CKM_AES_CMAC:
	case SKS_CKM_AES_CMAC_GENERAL:
	case SKS_CKM_AES_XCBC_MAC:
		if (key_class == SKS_CKO_SECRET_KEY &&
		    key_type == SKS_CKK_AES)
			break;

		DMSG("%s invalid key %s/%s", sks2str_proc(proc_id),
			sks2str_class(key_class), sks2str_key_type(key_type));
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;

	case SKS_CKM_MD5_HMAC:
	case SKS_CKM_SHA_1_HMAC:
	case SKS_CKM_SHA224_HMAC:
	case SKS_CKM_SHA256_HMAC:
	case SKS_CKM_SHA384_HMAC:
	case SKS_CKM_SHA512_HMAC:
		if (key_class != SKS_CKO_SECRET_KEY)
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;

		if (key_type == SKS_CKK_GENERIC_SECRET)
			break;

		switch (proc_id) {
		case SKS_CKM_MD5_HMAC:
			if (key_type == SKS_CKK_MD5_HMAC)
				break;
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;

		case SKS_CKM_SHA_1_HMAC:
			if (key_type == SKS_CKK_SHA_1_HMAC)
				break;
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case SKS_CKM_SHA224_HMAC:
			if (key_type == SKS_CKK_SHA224_HMAC)
				break;
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case SKS_CKM_SHA256_HMAC:
			if (key_type == SKS_CKK_SHA256_HMAC)
				break;
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case SKS_CKM_SHA384_HMAC:
			if (key_type == SKS_CKK_SHA384_HMAC)
				break;
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case SKS_CKM_SHA512_HMAC:
			if (key_type == SKS_CKK_SHA512_HMAC)
				break;
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		default:
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;

	case SKS_CKM_ECDSA:
	case SKS_CKM_ECDSA_SHA1:
	case SKS_CKM_ECDSA_SHA224:
	case SKS_CKM_ECDSA_SHA256:
	case SKS_CKM_ECDSA_SHA384:
	case SKS_CKM_ECDSA_SHA512:
	case SKS_CKM_ECDH1_DERIVE:
	case SKS_CKM_ECDH1_COFACTOR_DERIVE:
	case SKS_CKM_ECMQV_DERIVE:
	case SKS_CKM_ECDH_AES_KEY_WRAP:
		if (key_type != SKS_CKK_EC ||
		    (key_class != SKS_CKO_PUBLIC_KEY &&
		     key_class != SKS_CKO_PRIVATE_KEY)) {
			EMSG("Invalid key %s for mechanism %s",
				sks2str_type(key_type, key_class),
				sks2str_proc(proc_id));
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;

	case SKS_CKM_RSA_PKCS:
	case SKS_CKM_RSA_9796:
	case SKS_CKM_RSA_X_509:
	case SKS_CKM_SHA1_RSA_PKCS:
	case SKS_CKM_RSA_PKCS_OAEP:
	case SKS_CKM_SHA1_RSA_PKCS_PSS:
	case SKS_CKM_SHA256_RSA_PKCS:
	case SKS_CKM_SHA384_RSA_PKCS:
	case SKS_CKM_SHA512_RSA_PKCS:
	case SKS_CKM_SHA256_RSA_PKCS_PSS:
	case SKS_CKM_SHA384_RSA_PKCS_PSS:
	case SKS_CKM_SHA512_RSA_PKCS_PSS:
	case SKS_CKM_SHA224_RSA_PKCS:
	case SKS_CKM_SHA224_RSA_PKCS_PSS:
	case SKS_CKM_RSA_AES_KEY_WRAP:
		if (key_type != SKS_CKK_RSA ||
		    (key_class != SKS_CKO_PUBLIC_KEY &&
		     key_class != SKS_CKO_PRIVATE_KEY)) {
			EMSG("Invalid key %s for mechanism %s",
				sks2str_type(key_type, key_class),
				sks2str_proc(proc_id));
			return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;

	default:
		DMSG("Invalid processing 0x%" PRIx32 " (%s)", proc_id,
			sks2str_proc(proc_id));
		return SKS_CKR_MECHANISM_INVALID;
	}

	if (!parent_key_complies_allowed_processings(proc_id, head)) {
		DMSG("Allowed mechanism failed");
		return SKS_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	return SKS_OK;
}

bool object_is_private(struct sks_attrs_head *head)
{
	if (get_class(head) == SKS_CKO_PRIVATE_KEY)
		return true;

	if (get_bool(head, SKS_CKA_PRIVATE))
		return true;

	return false;
}

/*
 * Add a CKA ID attribute to an object or paired object if missing.
 * If 2 objects are provided and at least 1 does not have a CKA_ID,
 * the 2 objects will have the same CKA_ID attribute.
 *
 * @attrs1 - Object
 * @attrs2 - Object paired to attrs1 or NULL
 * Return an SKS return code
 */
uint32_t add_missing_attribute_id(struct sks_attrs_head **attrs1,
				  struct sks_attrs_head **attrs2)
{
	uint32_t rv;
	void *id1;
	size_t id1_size;
	void *id2;
	size_t id2_size;

	rv = get_attribute_ptr(*attrs1, SKS_CKA_ID, &id1, &id1_size);
	if (rv) {
		if (rv != SKS_NOT_FOUND)
			return rv;
		id1 = NULL;
	}

	if (attrs2) {
		rv = get_attribute_ptr(*attrs2, SKS_CKA_ID, &id2, &id2_size);
		if (rv) {
			if (rv != SKS_NOT_FOUND)
				return rv;
			id2 = NULL;
		}

		if (id1 && id2)
			return SKS_OK;

		if (id1 && !id2)
			return add_attribute(attrs2, SKS_CKA_ID, id1, id1_size);

		if (!id1 && id2)
			return add_attribute(attrs1, SKS_CKA_ID, id2, id2_size);
	} else {
		if (id1)
			return SKS_OK;
	}

	id1_size = SKS_CKA_DEFAULT_SIZE;
	id1 = TEE_Malloc(id1_size, 0);
	if (!id1)
		return SKS_MEMORY;

	TEE_GenerateRandom(id1, (uint32_t)id1_size);

	rv = add_attribute(attrs1, SKS_CKA_ID, id1, id1_size);
	if (rv == SKS_OK && attrs2)
		rv = add_attribute(attrs2, SKS_CKA_ID, id1, id1_size);

	TEE_Free(id1);

	return rv;
}

bool attribute_is_exportable(struct sks_attribute_head *req_attr,
			     struct sks_object *obj)
{
	uint8_t boolval;
	size_t boolsize;
	uint32_t rv;

	switch (req_attr->id) {
	case SKS_CKA_PRIVATE_EXPONENT:
	case SKS_CKA_PRIME_1:
	case SKS_CKA_PRIME_2:
	case SKS_CKA_EXPONENT_1:
	case SKS_CKA_EXPONENT_2:
	case SKS_CKA_COEFFICIENT:
		boolsize = sizeof(boolval);
		rv = get_attribute(obj->attributes, SKS_CKA_EXTRACTABLE,
				   &boolval, &boolsize);
		if (rv || boolval == SKS_FALSE)
			return false;

		boolsize = sizeof(boolval);
		rv = get_attribute(obj->attributes, SKS_CKA_SENSITIVE,
				   &boolval, &boolsize);
		if (rv || boolval == SKS_TRUE)
			return false;
		break;
	default:
		break;
	}

	return true;
}
