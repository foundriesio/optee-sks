// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <sks_internal_abi.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "serializer.h"
#include "sks_helpers.h"

/*
 * Util routines for serializes unformatted arguments in a client memref
 */
void serialargs_init(struct serialargs *args, void *in, size_t size)
{
	args->start = in;
	args->next = in;
	args->size = size;
}

uint32_t serialargs_get(struct serialargs *args, void *out, size_t size)
{
	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return SKS_BAD_PARAM;
	}

	TEE_MemMove(out, args->next, size);

	args->next += size;

	return SKS_OK;
}

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				  void **out, size_t size)
{
	void *ptr;

	if (!size) {
		*out = NULL;
		return SKS_OK;
	}

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return SKS_BAD_PARAM;
	}

	ptr = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	if (!ptr)
		return SKS_MEMORY;

	TEE_MemMove(ptr, args->next, size);

	args->next += size;
	*out = ptr;

	return SKS_OK;
}

uint32_t serialargs_get_ptr(struct serialargs *args, void **out, size_t size)
{
	void *ptr = args->next;

	if (!size) {
		*out = NULL;
		return SKS_OK;
	}

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return SKS_BAD_PARAM;
	}

	args->next += size;
	*out = ptr;

	return SKS_OK;
}

uint32_t serialargs_alloc_get_one_attribute(struct serialargs *args __unused,
					    struct sks_attribute_head **out __unused)
{
	struct sks_attribute_head head;
	size_t out_size = sizeof(head);
	void *pref;

	if (args->next + out_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect at least %zd",
		     args->size, args->size - (args->next - args->start),
		     out_size);
		return SKS_BAD_PARAM;
	}

	TEE_MemMove(&head, args->next, out_size);

	out_size += head.size;
	if (args->next + out_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start),
		     out_size);
		return SKS_BAD_PARAM;
	}

	pref = TEE_Malloc(out_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!pref)
		return SKS_MEMORY;

	TEE_MemMove(pref, args->next, out_size);
	args->next += out_size;

	*out = pref;

	return SKS_OK;
}

uint32_t serialargs_alloc_get_attributes(struct serialargs *args __unused,
					 struct sks_object_head **out __unused)
{
	struct sks_object_head attr;
	struct sks_object_head *pattr;
	size_t attr_size = sizeof(attr);

	if (args->next + attr_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect at least %zd",
		     args->size, args->size - (args->next - args->start),
		     attr_size);
		return SKS_BAD_PARAM;
	}

	TEE_MemMove(&attr, args->next, attr_size);

	attr_size += attr.attrs_size;
	if (args->next + attr_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start),
		     attr_size);
		return SKS_BAD_PARAM;
	}

	pattr = TEE_Malloc(attr_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!pattr)
		return SKS_MEMORY;

	TEE_MemMove(pattr, args->next, attr_size);
	args->next += attr_size;

	*out = pattr;

	return SKS_OK;
}

/*
 * serialize - serialize input data in buffer
 *
 * Serialize data in provided buffer.
 * Insure 64byte alignement of appended data in the buffer.
 */
uint32_t serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf;
	size_t nlen = *blen + len;

	buf = TEE_Realloc(*bstart, nlen);
	if (!buf)
		return SKS_MEMORY;

	TEE_MemMove(buf + *blen, data, len);

	*blen = nlen;
	*bstart = buf;

	return SKS_OK;
}
