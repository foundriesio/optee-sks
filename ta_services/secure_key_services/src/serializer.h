/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#ifndef __SERIALIZER_H__
#define __SERIALIZER_H__

#include <sks_internal_abi.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_internal_api.h>

/*
 * Util routines for serializes unformated arguments in a client memref
 */
struct serialargs {
	char *start;
	char *next;
	size_t size;
};

void serialargs_init(struct serialargs *args, void *in, size_t size);

uint32_t serialargs_get(struct serialargs *args, void *out, size_t sz);

uint32_t serialargs_get_ptr(struct serialargs *args, void **out, size_t size);

uint32_t serialargs_alloc_and_get_sks_reference(struct serialargs *args,
						struct sks_attribute_head **out);

uint32_t serialargs_alloc_and_get_sks_attributes(struct serialargs *args,
						 struct sks_object_head **out);

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				   void **out, size_t size);

#define SKS_MAX_BOOLPROP_SHIFT	64
#define SKS_MAX_BOOLPROP_ARRAY	(SKS_MAX_BOOLPROP_SHIFT / sizeof(uint32_t))

/**
 * serialize - Append data into a serialized buffer
 */
uint32_t serialize(char **bstart, size_t *blen, void *data, size_t len);

#endif /*__SERIALIZER_H*/

