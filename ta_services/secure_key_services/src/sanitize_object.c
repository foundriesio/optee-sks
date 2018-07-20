/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <stdlib.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "attributes.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "sks_helpers.h"

/*
 * Functions to generate a serialized object.
 * References are pointers to struct serializer.
 */
#define SKS_ID(sks)			case sks:

static bool consistent_class_and_type(uint32_t object, uint32_t type)
{
	switch (object) {
	case SKS_CKO_DATA:
		return true;
	case SKS_CKO_SECRET_KEY:
		return id_is_sks_key_type(type);
	case SKS_CKO_MECHANISM:
		return id_is_sks_mechanism(type);
	case SKS_CKO_PUBLIC_KEY:
	case SKS_CKO_PRIVATE_KEY:
	case SKS_CKO_OTP_KEY:
	case SKS_CKO_CERTIFICATE:
	case SKS_CKO_DOMAIN_PARAMETERS:
	case SKS_CKO_HW_FEATURE:
	default:
		return false;
	}

	return false;
}

/* Sanitize class/type in a client attribute list */
static uint32_t sanitize_class_and_type(struct sks_attrs_head **dst,
				     void *src)
{
	struct sks_object_head head;
	char *cur;
	char *end;
	size_t len;
	uint32_t class_found;
	uint32_t type_found;
	struct sks_attribute_head cli_ref;
	uint32_t __maybe_unused rc;

	TEE_MemMove(&head, src, sizeof(struct sks_object_head));

	class_found = SKS_UNDEFINED_ID;
	type_found = SKS_UNDEFINED_ID;

	cur = (char *)src + sizeof(struct sks_object_head);
	end = cur + head.attrs_size;

	for (; cur < end; cur += len) {
		/* Structure aligned copy of client reference in the object */
		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		len = sizeof(cli_ref) + cli_ref.size;


		if (sks_attr_is_class(cli_ref.id)) {
			uint32_t class;

			if (cli_ref.size != sks_attr_is_class(cli_ref.id))
				return SKS_CKR_TEMPLATE_INCONSISTENT;

			TEE_MemMove(&class, cur + sizeof(cli_ref), cli_ref.size);

			if (class_found != SKS_UNDEFINED_ID &&
			    class_found != class) {
				EMSG("Conflicting class value");
				return SKS_CKR_TEMPLATE_INCONSISTENT;
			}

			class_found = class;
			continue;
		}

		/* The attribute is a type-in-class */
		if (sks_attr_is_type(cli_ref.id)) {
			uint32_t type;

			if (cli_ref.size != sks_attr_is_type(cli_ref.id))
				return SKS_CKR_TEMPLATE_INCONSISTENT;

			TEE_MemMove(&type, cur + sizeof(cli_ref), cli_ref.size);

			if (type_found != SKS_UNDEFINED_ID &&
			    type_found != type) {
				EMSG("Conflicting type-in-class value");
				return SKS_CKR_TEMPLATE_INCONSISTENT;
			}

			type_found = type;
		}
	}

	/* Sanity */
	if (cur != end) {
		EMSG("Unexpected alignment issue");
		return SKS_FAILED;
	}

	if (!consistent_class_and_type(class_found, type_found)) {
		MSG("inconsistent class/type");
		return SKS_CKR_TEMPLATE_INCONSISTENT;
	}

#ifdef SKS_SHEAD_WITH_TYPE
	(*dst)->class = class_found;
	(*dst)->type = type_found;
#else
	rc = add_attribute(dst, SKS_CKA_CLASS, &class_found, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = add_attribute(dst, SKS_CKA_KEY_TYPE, &type_found,
			   sizeof(uint32_t));
	if (rc)
		return rc;
#endif

	return SKS_OK;
}

static uint32_t sanitize_boolprop(struct sks_attrs_head __maybe_unused **dst,
				struct sks_attribute_head *cli_ref,
				char *cur, uint32_t *boolprop_base,
				uint32_t *sanity)
{
	int shift;
	uint32_t mask;
	uint32_t value;
	uint32_t *boolprop_ptr;
	uint32_t *sanity_ptr;

	/* Get the booloean property shift position and value */
	shift = sks_attr2boolprop_shift(cli_ref->id);
	if (shift < 0)
		return SKS_NOT_FOUND;

	if (shift >= SKS_MAX_BOOLPROP_SHIFT)
		return SKS_FAILED;

	mask = 1 << (shift % 32);
	if ((*(uint8_t *)(cur + sizeof(*cli_ref))) == SKS_TRUE)
		value = mask;
	else
		value = 0;

	/* Locate the current config value for the boolean property */
	boolprop_ptr = boolprop_base + (shift / 32);
	sanity_ptr = sanity + (shift / 32);

	/* Error if already set to a different boolean value */
	if (*sanity_ptr & mask && value != (*boolprop_ptr & mask))
		return SKS_CKR_TEMPLATE_INCONSISTENT;

	if (value)
		*boolprop_ptr |= mask;
	else
		*boolprop_ptr &= ~mask;

#ifndef SKS_SHEAD_WITH_BOOLPROPS
	/* Store the attribute inside the serialized data */
	if (!(*sanity_ptr & mask)) {
		uint32_t rc;
		uint8_t sks_bool = !!value;

		rc = add_attribute(dst, SKS_BOOLPROPS_BASE + shift,
				   &sks_bool, sizeof(uint8_t));
		if (rc)
			return rc;
	}
#endif

	*sanity_ptr |= mask;

	return SKS_OK;
}

static uint32_t sanitize_boolprops(struct sks_attrs_head **dst, void *src)
{
	struct sks_object_head head;
	char *cur;
	char *end;
	size_t len;
	struct sks_attribute_head cli_ref;
	uint32_t sanity[SKS_MAX_BOOLPROP_ARRAY] = { 0 };
	uint32_t boolprops[SKS_MAX_BOOLPROP_ARRAY] = { 0 };
	uint32_t rc;

	TEE_MemMove(&head, src, sizeof(struct sks_object_head));

	cur = (char *)src + sizeof(struct sks_object_head);
	end = cur + head.attrs_size;

	for (; cur < end; cur += len) {
		/* Structure aligned copy of the cli_ref in the object */
		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		len = sizeof(cli_ref) + cli_ref.size;

		rc = sanitize_boolprop(dst, &cli_ref, cur, boolprops, sanity);
		if (rc != SKS_OK && rc != SKS_NOT_FOUND)
			return rc;
	}

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	(*dst)->boolpropl = boolprops[0];
	(*dst)->boolproph = boolprops[1];
#endif

	return SKS_OK;
}

/* Counterpart of serialize_indirect_attribute() */
static uint32_t sanitize_indirect_attr(struct sks_attrs_head **dst,
					struct sks_attribute_head *cli_ref,
					char *cur)
{
	struct sks_attrs_head *obj2;
	uint32_t rc;
	uint32_t class = get_class(*dst);

	if (class == SKS_UNDEFINED_ID)
		return SKS_ERROR;

	/*
	 * Serialized attributes: current applicable only the key templates which
	 * are tables of attributes.
	 */
	switch (cli_ref->id) {
	case SKS_CKA_WRAP_TEMPLATE:
	case SKS_CKA_UNWRAP_TEMPLATE:
	case SKS_CKA_DERIVE_TEMPLATE:
		break;
	default:
		return SKS_NOT_FOUND;
	}
	/* Such attributes are expected only for keys (and vendor defined) */
	if (sks_attr_class_is_key(class))
		return SKS_CKR_TEMPLATE_INCONSISTENT;

	init_attributes_head(&obj2);

	/* Build a new serial object while sanitizing the attributes list */
	rc = sanitize_client_object(&obj2, cur + sizeof(*cli_ref),
				    cli_ref->size);
	if (rc)
		return rc;

	return add_attribute(dst, cli_ref->id, obj2,
			     sizeof(struct sks_attrs_head) + obj2->attrs_size);
}

uint32_t sanitize_client_object(struct sks_attrs_head **dst,
				void *src, size_t size)
{
	struct sks_object_head head;
	uint32_t rc;
	char *cur;
	char *end;
	size_t next;

	if (size < sizeof(struct sks_object_head))
		return SKS_BAD_PARAM;

	TEE_MemMove(&head, src, sizeof(struct sks_object_head));

	if (size < (sizeof(struct sks_object_head) + head.attrs_size))
		return SKS_BAD_PARAM;

	init_attributes_head(dst);

	rc = sanitize_class_and_type(dst, src);
	if (rc)
		goto bail;

	rc = sanitize_boolprops(dst, src);
	if (rc)
		goto bail;

	cur = (char *)src + sizeof(struct sks_object_head);
	end = cur + head.attrs_size;

	for (; cur < end; cur += next) {
		struct sks_attribute_head cli_ref;

		TEE_MemMove(&cli_ref, cur, sizeof(cli_ref));
		next = sizeof(cli_ref) + cli_ref.size;

		if (sks_attr_is_class(cli_ref.id) ||
		    sks_attr_is_type(cli_ref.id) ||
		    sks_attr2boolprop_shift(cli_ref.id) >= 0)
			continue;

		rc = sanitize_indirect_attr(dst, &cli_ref, cur);
		if (rc == SKS_OK)
			continue;
		if (rc != SKS_NOT_FOUND)
			goto bail;

		if (!valid_sks_attribute_id(cli_ref.id, cli_ref.size)) {
			EMSG("Invalid attribute id %" PRIx32, cli_ref.id);
			rc = SKS_CKR_TEMPLATE_INCONSISTENT;
			goto bail;
		}

		rc = add_attribute(dst, cli_ref.id, cur + sizeof(cli_ref),
				   cli_ref.size);
		if (rc)
			goto bail;
	}

	/* sanity */
	if (cur != end) {
		EMSG("Unexpected alignment inssue");
		rc = SKS_FAILED;
		goto bail;
	}

bail:
	return rc;
}

/*
 * Debug: dump object attribute array to output trace
 */

static uint32_t __trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
	char *prefix2;
	size_t prefix_len = strlen(prefix);
	char *cur = src;
	uint32_t rc;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return SKS_MEMORY;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next) {
		struct sks_ref sks_ref;
		uint8_t data[4] = { 0 };
		uint32_t data_u32;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		TEE_MemMove(&data[0], cur + sizeof(sks_ref),
			    MIN(sks_ref.size, sizeof(data)));
		TEE_MemMove(&data_u32, cur + sizeof(sks_ref), sizeof(data_u32));

		next = sizeof(sks_ref) + sks_ref.size;

		IMSG_RAW("%s Attr %s / %s (0x%04" PRIx32 " %" PRIu32 "-byte)",
			prefix, sks2str_attr(sks_ref.id),
			sks2str_attr_value(sks_ref.id, sks_ref.size,
					   cur + sizeof(sks_ref)),
			sks_ref.id, sks_ref.size);

		switch (sks_ref.size) {
		case 0:
			break;
		case 1:
			DMSG_RAW("%s Attr byte value: %02x", prefix, data[0]);
			break;
		case 2:
			DMSG_RAW("%s Attr byte value: %02x %02x",
				 prefix, data[0], data[1]);
			break;
		case 3:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x",
				 prefix, data[0], data[1], data[2]);
			break;
		case 4:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x %02x",
				 prefix, data[0], data[1], data[2], data[3]);
			break;
		default:
			DMSG_RAW("%s Attr byte value: %02x %02x %02x %02x ...",
				 prefix, data[0], data[1], data[2], data[3]);
			break;
		}

		switch (sks_ref.id) {
		case SKS_CKA_WRAP_TEMPLATE:
		case SKS_CKA_UNWRAP_TEMPLATE:
		case SKS_CKA_DERIVE_TEMPLATE:
			rc = trace_attributes_from_api_head(prefix2,
							cur + sizeof(sks_ref),
							(char *)end - cur);
			if (rc)
				return rc;
			break;
		default:
			break;
		}
	}

	/* Sanity */
	if (cur != (char *)end) {
		EMSG("Warning: unexpected alignment issue");
	}

	TEE_Free(prefix2);
	return SKS_OK;
}

uint32_t trace_attributes_from_api_head(const char *prefix,
					void *ref, size_t size)
{
	struct sks_object_head head;
	char *pre;
	size_t offset;
	uint32_t rc;

	TEE_MemMove(&head, ref, sizeof(head));

	if (size > sizeof(head) + head.attrs_size) {
		EMSG("template overflows client buffer (%u/%u)",
			size, sizeof(head) + head.attrs_size);
		return SKS_FAILED;
	}


	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre)
		return SKS_MEMORY;
	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	IMSG_RAW("%s,--- (serial object) Attributes list --------", pre);
	IMSG_RAW("%s| %" PRIx32 " item(s) - %" PRIu32 " bytes",
		pre, head.attrs_count, head.attrs_size);

	offset = sizeof(head);
	pre[prefix ? strlen(prefix) : 0] = '|';
	rc = __trace_attributes(pre, (char *)ref + offset,
			      (char *)ref + offset + head.attrs_size);
	if (rc)
		goto bail;

	IMSG_RAW("%s`-----------------------", prefix ? prefix : "");

bail:
	TEE_Free(pre);
	return rc;
}
