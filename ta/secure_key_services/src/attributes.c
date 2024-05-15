/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <compiler.h>
#include <sks_internal_abi.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <util.h>

#include "attributes.h"
#include "sks_helpers.h"
#include "serializer.h"

uint32_t init_attributes_head(struct sks_attrs_head **head)
{
	*head = TEE_Malloc(sizeof(struct sks_attrs_head), TEE_MALLOC_FILL_ZERO);
	if (!*head)
		return SKS_MEMORY;

#ifdef SKS_SHEAD_WITH_TYPE
	(*head)->class = SKS_UNDEFINED_ID;
	(*head)->type = SKS_UNDEFINED_ID;
#endif

	return SKS_OK;
}

#if defined(SKS_SHEAD_WITH_TYPE) || defined(SKS_SHEAD_WITH_BOOLPROPS)
static bool attribute_is_in_head(uint32_t attribute)
{
#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CKA_CLASS || sks_attr_is_type(attribute))
		return true;
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	if (sks_attr2boolprop_shift(attribute) >= 0)
		return true;
#endif

	return false;
}
#endif

uint32_t add_attribute(struct sks_attrs_head **head,
			uint32_t attribute, void *data, size_t size)
{
	size_t buf_len = sizeof(struct sks_attrs_head) + (*head)->attrs_size;
	uint32_t rv = 0;
	uint32_t data32 = 0;
	char **bstart = (void *)head;
	int __maybe_unused shift = 0;

#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CKA_CLASS || sks_attr_is_type(attribute)) {
		assert(size == sizeof(uint32_t));

		TEE_MemMove(attribute == SKS_CKA_CLASS ?
				&(*head)->class : &(*head)->type,
				data, sizeof(uint32_t));

		return SKS_OK;
	}
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	shift = sks_attr2boolprop_shift(attribute);
	if (head_contains_boolprops(*head) && shift >= 0) {
		uint32_t mask = shift < 32 ? BIT(shift) : BIT(shift - 32);
		uint32_t val = *(uint8_t *)data ? mask : 0;

		if (size != sizeof(uint8_t)) {
			EMSG("Invalid size %zu", size);
			return SKS_CKR_TEMPLATE_INCONSISTENT;
		}

		if (shift < 32)
			(*head)->boolpropl = ((*head)->boolpropl & ~mask) | val;
		else
			(*head)->boolproph = ((*head)->boolproph & ~mask) | val;

		return SKS_OK;
	}
#endif

	data32 = attribute;
	rv = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	data32 = size;
	rv = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialize(bstart, &buf_len, data, size);
	if (rv)
		return rv;

	/* Alloced buffer is always 64byte align, safe for us */
	head = (void *)bstart;
	(*head)->attrs_size += 2 * sizeof(uint32_t) + size;
	(*head)->attrs_count++;

	return rv;
}

uint32_t remove_attribute(struct sks_attrs_head **head, uint32_t attribute)
{
	struct sks_attrs_head *h = *head;
	char *cur = NULL;
	char *end = NULL;
	size_t next_off = 0;

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	/* Can't remove an attribute that is defined in the head */
	if (head_contains_boolprops(*head) && attribute_is_in_head(attribute)) {
		EMSG("Can't remove attribute from the head");
		return SKS_FAILED;
	}
#endif

	/* Let's find the target attribute */
	cur = (char *)h + sizeof(struct sks_attrs_head);
	end = cur + h->attrs_size;
	for (; cur < end; cur += next_off) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->attrs_count--;
		h->attrs_size -= next_off;
		end -= next_off;
		next_off = 0;
		return SKS_OK;
	}

	DMSG("SKS_VALUE not found");
	return SKS_NOT_FOUND;
}

uint32_t remove_attribute_check(struct sks_attrs_head **head, uint32_t attribute,
				size_t max_check)
{
	struct sks_attrs_head *h = *head;
	char *cur = NULL;
	char *end = NULL;
	size_t next_off = 0;
	size_t found = 0;

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	/* Can't remove an attribute that is defined in the head */
	if (head_contains_boolprops(*head) && attribute_is_in_head(attribute)) {
		EMSG("Can't remove attribute from the head");
		TEE_Panic(0);
	}
#endif

	/* Let's find the target attribute */
	cur = (char *)h + sizeof(struct sks_attrs_head);
	end = cur + h->attrs_size;
	for (; cur < end; cur += next_off) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		found++;
		if (found > max_check) {
			DMSG("Too many attribute occurrences");
			return SKS_FAILED;
		}

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->attrs_count--;
		h->attrs_size -= next_off;
		end -= next_off;
		next_off = 0;
	}

	/* sanity */
	if (cur != end) {
		EMSG("Bad end address");
		return SKS_ERROR;
	}

	if (!found) {
		EMSG("SKS_VALUE not found");
		return SKS_FAILED;

	}

	return SKS_OK;
}

void get_attribute_ptrs(struct sks_attrs_head *head, uint32_t attribute,
			void **attr, uint32_t *attr_size, size_t *count)
{
	char *cur = (char *)head + sizeof(struct sks_attrs_head);
	char *end = cur + head->attrs_size;
	size_t next_off = 0;
	size_t max_found = *count;
	size_t found = 0;
	void **attr_ptr = attr;
	uint32_t *attr_size_ptr = attr_size;

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	/* Can't return a pointer to a boolprop attribute */
	if (head_contains_boolprops(head) && attribute_is_in_head(attribute)) {
		EMSG("Can't get pointer to an attribute in the head");
		TEE_Panic(0);
	}
#endif

	for (; cur < end; cur += next_off) {
		/* Structure aligned copy of the sks_ref in the object */
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		found++;

		if (!max_found)
			continue;	/* only count matching attributes */

		if (attr)
			*attr_ptr++ = cur + sizeof(sks_ref);

		if (attr_size)
			*attr_size_ptr++ = sks_ref.size;

		if (found == max_found)
			break;
	}

	/* Sanity */
	if (cur > end) {
		DMSG("Exceeding serial object length");
		TEE_Panic(0);
	}

	*count = found;
}

uint32_t get_attribute_ptr(struct sks_attrs_head *head, uint32_t attribute,
			   void **attr_ptr, uint32_t *attr_size)
{
	size_t count = 1;

#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CKA_CLASS) {
		if (attr_size)
			*attr_size = sizeof(uint32_t);
		if (attr_ptr)
			*attr_ptr = &head->class;

		return SKS_OK;
	}
	if (attribute == SKS_CKA_KEY_TYPE) {
		if (attr_size)
			*attr_size = sizeof(uint32_t);
		if (attr_ptr)
			*attr_ptr = &head->type;

		return SKS_OK;
	}
#endif
#ifdef SKS_SHEAD_WITH_BOOLPROPS
	if (head_contains_boolprops(head) &&
	    sks_attr2boolprop_shift(attribute) >= 0)
		TEE_Panic(0);
#endif

	get_attribute_ptrs(head, attribute, attr_ptr, attr_size, &count);

	if (!count)
		return SKS_NOT_FOUND;

	if (count != 1)
		return SKS_ERROR;

	return SKS_OK;
}

uint32_t get_attribute(struct sks_attrs_head *head, uint32_t attribute,
			void *attr, uint32_t *attr_size)
{
	uint32_t rc = 0;
	void *attr_ptr = NULL;
	uint32_t size = 0;
	uint8_t __maybe_unused bbool = 0;
	int __maybe_unused shift = 0;

#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CKA_CLASS) {
		size = sizeof(uint32_t);
		attr_ptr = &head->class;
		goto found;
	}

	if (attribute == SKS_CKA_KEY_TYPE) {
		size = sizeof(uint32_t);
		attr_ptr = &head->type;
		goto found;
	}
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	shift = sks_attr2boolprop_shift(attribute);
	if (head_contains_boolprops(head) && shift >= 0) {
		uint32_t *boolprop = NULL;

		boolprop = (shift < 32) ? &head->boolpropl : &head->boolproph;
		bbool = (*boolprop & (1 << (shift % 32))) ? SKS_TRUE : SKS_FALSE;

		size = sizeof(uint8_t);
		attr_ptr = &bbool;
		goto found;
	}
#endif
	rc = get_attribute_ptr(head, attribute, &attr_ptr, &size);
	if (rc == SKS_OK)
		goto found;

	return rc;

found:
	if (attr_size && *attr_size < size) {
		*attr_size = size;
		/* This reuses buffer-to-small for any bad size matching */
		return SKS_SHORT_BUFFER;
	}

	if (attr)
		TEE_MemMove(attr, attr_ptr, size);

	if (attr_size)
		*attr_size = size;

	return SKS_OK;
}

bool get_bool(struct sks_attrs_head *head, uint32_t attribute)
{
	uint32_t __maybe_unused rc = 0;
	uint8_t bbool = 0;
	uint32_t size = sizeof(bbool);
	int __maybe_unused shift = 0;

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	shift = sks_attr2boolprop_shift(attribute);
	if (shift < 0)
		TEE_Panic(SKS_NOT_FOUND);

	if (head_contains_boolprops(head)) {
		if (shift > 31)
			return head->boolproph & BIT(shift - 32);
		else
			return head->boolpropl & BIT(shift);
	}
#endif

	rc = get_attribute(head, attribute, &bbool, &size);

	if (rc == SKS_NOT_FOUND)
		return false;

	assert(rc == SKS_OK);
	return !!bbool;
}

bool attributes_match_reference(struct sks_attrs_head *candidate,
				struct sks_attrs_head *ref)
{
	size_t count = ref->attrs_count;
	unsigned char *ref_attr = ref->attrs;
	uint32_t rc = 0;

	if (!ref->attrs_count) {
		DMSG("Empty reference: no match");
		return false;
	}

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	/*
	 * All boolprops attributes must be explicitly defined
	 * as an attribute reference in the reference object.
	 */
	assert(!head_contains_boolprops(ref));
#endif

	for (count = 0; count < ref->attrs_count; count++) {
		struct sks_ref sks_ref;
		void *found = NULL;
		uint32_t size = 0;
		int shift = 0;

		TEE_MemMove(&sks_ref, ref_attr, sizeof(sks_ref));

		shift = sks_attr2boolprop_shift(sks_ref.id);
		if (shift >= 0) {
			bool bb_ref = get_bool(ref, sks_ref.id);
			bool bb_candidate = get_bool(candidate, sks_ref.id);

			if (bb_ref != bb_candidate) {
				return false;
			}
		} else {
			rc = get_attribute_ptr(candidate, sks_ref.id,
					       &found, &size);

			if (rc || !found || size != sks_ref.size ||
			    TEE_MemCompare(ref_attr + sizeof(sks_ref),
					   found, size)) {
				return false;
			}
		}

		ref_attr += sizeof(sks_ref) + sks_ref.size;
	}

	return true;
}

/*
 * Debug: dump CK attribute array to output trace
 */
#define ATTR_TRACE_FMT	"%s attr %s / %s\t(0x%04" PRIx32 " %" PRIu32 "-byte"
#define ATTR_FMT_0BYTE	ATTR_TRACE_FMT ")"
#define ATTR_FMT_1BYTE	ATTR_TRACE_FMT ": %02x)"
#define ATTR_FMT_2BYTE	ATTR_TRACE_FMT ": %02x %02x)"
#define ATTR_FMT_3BYTE	ATTR_TRACE_FMT ": %02x %02x %02x)"
#define ATTR_FMT_4BYTE	ATTR_TRACE_FMT ": %02x %02x %02x %02x)"
#define ATTR_FMT_ARRAY	ATTR_TRACE_FMT ": %02x %02x %02x %02x ...)"

static uint32_t __trace_attributes(char *prefix, void *src, void *end)
{
	size_t next_off = 0;
	char *prefix2 = NULL;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return SKS_MEMORY;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next_off) {
		struct sks_ref sks_ref;
		uint8_t data[4] = { 0 };

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		TEE_MemMove(&data[0], cur + sizeof(sks_ref),
			    MIN(sks_ref.size, sizeof(data)));

		next_off = sizeof(sks_ref) + sks_ref.size;

		switch (sks_ref.size) {
		case 0:
			IMSG_RAW(ATTR_FMT_0BYTE,
				 prefix, sks2str_attr(sks_ref.id), "*",
				 sks_ref.id, sks_ref.size);
			break;
		case 1:
			IMSG_RAW(ATTR_FMT_1BYTE,
				 prefix, sks2str_attr(sks_ref.id),
				 sks2str_attr_value(sks_ref.id, sks_ref.size,
						    cur + sizeof(sks_ref)),
				 sks_ref.id, sks_ref.size, data[0]);
			break;
		case 2:
			IMSG_RAW(ATTR_FMT_2BYTE,
				 prefix, sks2str_attr(sks_ref.id),
				 sks2str_attr_value(sks_ref.id, sks_ref.size,
						    cur + sizeof(sks_ref)),
				 sks_ref.id, sks_ref.size, data[0], data[1]);
			break;
		case 3:
			IMSG_RAW(ATTR_FMT_3BYTE,
				 prefix, sks2str_attr(sks_ref.id),
				 sks2str_attr_value(sks_ref.id, sks_ref.size,
						    cur + sizeof(sks_ref)),
				 sks_ref.id, sks_ref.size,
				 data[0], data[1], data[2]);
			break;
		case 4:
			IMSG_RAW(ATTR_FMT_4BYTE,
				 prefix, sks2str_attr(sks_ref.id),
				 sks2str_attr_value(sks_ref.id, sks_ref.size,
						    cur + sizeof(sks_ref)),
				 sks_ref.id, sks_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		default:
			IMSG_RAW(ATTR_FMT_ARRAY,
				 prefix, sks2str_attr(sks_ref.id),
				 sks2str_attr_value(sks_ref.id, sks_ref.size,
						    cur + sizeof(sks_ref)),
				 sks_ref.id, sks_ref.size,
				 data[0], data[1], data[2], data[3]);
			break;
		}

		switch (sks_ref.id) {
		case SKS_CKA_WRAP_TEMPLATE:
		case SKS_CKA_UNWRAP_TEMPLATE:
		case SKS_CKA_DERIVE_TEMPLATE:
			trace_attributes(prefix2,
					 (void *)(cur + sizeof(sks_ref)));
			break;
		default:
			break;
		}
	}

	/* Sanity */
	if (cur != (char *)end) {
		EMSG("Warning: unexpected alignment in object attributes");
	}

	TEE_Free(prefix2);
	return SKS_OK;
}

#ifdef SKS_SHEAD_WITH_BOOLPROPS
static void trace_boolprops(const char *prefix, struct sks_attrs_head *head)
{
	size_t __maybe_unused n = 0;

	for (n = 0; n <= SKS_BOOLPROPS_LAST; n++) {
		bool bp = n < 32 ? !!(head->boolpropl & BIT(n)) :
				 !!(head->boolproph & BIT(n - 32));

		IMSG_RAW("%s| attr %s / %s (0x%" PRIx32 ")",
			 prefix, sks2str_attr(n), bp ? "TRUE" : "FALSE", n);
	}
}
#endif

uint32_t trace_attributes(const char *prefix, void *ref)
{
	struct sks_attrs_head head;
	char *pre = NULL;
	uint32_t rc = 0;
	size_t __maybe_unused n = 0;

	TEE_MemMove(&head, ref, sizeof(head));

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre)
		return SKS_MEMORY;
	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	IMSG_RAW("%s,--- (serial object) Attributes list --------", pre);
	IMSG_RAW("%s| %" PRIu32 " item(s) - %" PRIu32 " bytes",
		pre, head.attrs_count, head.attrs_size);
#ifdef SKS_SHEAD_WITH_TYPE
	IMSG_RAW("%s| class (0x%" PRIx32 ") %s type (0x%" PRIx32 ") %s",
		 pre, head.class, sks2str_class(head.class),
		 head.type, sks2str_type(head.type, head.class));
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	if (head_contains_boolprops(&head))
		trace_boolprops(pre, &head);
#endif

	pre[prefix ? strlen(prefix) : 0] = '|';
	rc = __trace_attributes(pre, (char *)ref + sizeof(head),
			        (char *)ref + sizeof(head) + head.attrs_size);
	if (rc)
		goto bail;

	IMSG_RAW("%s`-----------------------", prefix ? prefix : "");

bail:
	TEE_Free(pre);
	return rc;
}
