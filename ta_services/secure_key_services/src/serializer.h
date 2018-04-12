/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIALIZER_H
#define __SERIALIZER_H

#include <sks_internal_abi.h>
#include <stdint.h>
#include <stddef.h>

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
						struct sks_reference **out);

uint32_t serialargs_alloc_and_get_sks_attributes(struct serialargs *args,
						 struct sks_object_head **out);

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				   void **out, size_t size);

#endif /*__SERIALIZER_H*/

