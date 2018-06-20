/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __HELPERS_CK_H
#define __HELPERS_CK_H

#include <pkcs11.h>
#include <stdint.h>
#include <stddef.h>
#include <sks_ta.h>
#include <tee_client_api.h>

/*
 * SKS reserves vendor ID 0xffffffff to represent an invalid ID
 * (attribute class, type, ...)
 */
#define CK_VENDOR_INVALID_ID		0xffffffff

/*
 * Convert structure struct sks_token_info retreived from TA into a
 * cryptoki API compliant CK_TOKEN_INFO structure.
 *
 * struct sks_token_info is defined in the SKS TA API.
 */
CK_RV sks2ck_token_info(CK_TOKEN_INFO_PTR ck_info,
			struct sks_token_info *sks_info);
CK_RV sks2ck_slot_info(CK_SLOT_INFO_PTR ck_info,
			struct sks_slot_info *sks_info);

CK_RV sks2ck_slot_flag(CK_FLAGS *ck, uint32_t sks);
CK_RV sks2ck_token_flag(CK_FLAGS *ck, uint32_t sks);

/*
 * Convert IDs between SKS and Cryptoki.
 */
CK_RV sks2ck_mechanism_type(CK_MECHANISM_TYPE *ck, uint32_t sks);
uint32_t ck2sks_mechanism_type(CK_MECHANISM_TYPE ck);

CK_RV sks2ck_attribute_id(CK_ULONG *ck, uint32_t sks);
uint32_t ck2sks_attribute_id(CK_ULONG ck);

CK_RV sks2ck_mechanism_type_list(CK_MECHANISM_TYPE *dst, void *sks,
				 size_t count);
CK_RV sks2ck_mechanism_flag(CK_FLAGS *ck, uint32_t sks);
CK_RV sks2ck_mechanism_info(CK_MECHANISM_INFO *info, void *sks);

uint32_t ck2sks_class(CK_ULONG ck);
CK_RV sks2ck_class(CK_ULONG *ck, uint32_t sks);

uint32_t ck2sks_type_in_class(CK_ULONG ck, CK_ULONG class);
CK_RV sks2ck_type_in_class(CK_ULONG *ck, uint32_t sks, CK_ULONG class);

uint32_t ck2sks_key_type(CK_ULONG ck);
CK_RV sks2ck_key_type(CK_ULONG *ck, uint32_t sks);

int sks_attr2boolprop_shift(CK_ULONG attr);

CK_RV sks2ck_rv(uint32_t sks);
CK_RV teec2ck_rv(TEEC_Result res);

/*
 * Helper functions to analyse CK fields
 */
size_t ck_attr_is_class(uint32_t attribute_id);
size_t ck_attr_is_type(uint32_t attribute_id);
int ck_attr2boolprop_shift(CK_ULONG attr);

int sks_object_has_boolprop(uint32_t class);
int sks_class_has_type(uint32_t class);

#endif /*__HELPERS_CK_H*/
