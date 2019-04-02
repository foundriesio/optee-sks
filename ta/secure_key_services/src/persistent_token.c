/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <sks_ta.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "pkcs11_token.h"
#include "sks_helpers.h"

/*
 * Token persistent objects
 *
 * The persistent objects are each identified by a UUID.
 * The persistent object database stores the list of the UUIDs registered. For
 * each it is expected that a file of ID "UUID" is store in the OP-TEE secure
 * storage.
 */

/* 'X' will be replaced by the token decimal id (up to 9!) */
#define TOKEN_DB_FILE_BASE		"token.db.X"

void close_persistent_db(struct ck_token *token)
{
	int n = 0;

	for (n = 0; n < SKS_MAX_USERS; n++) {
		TEE_CloseObject(token->pin_hdl[n]);
		token->pin_hdl[n] = TEE_HANDLE_NULL;
	}

	TEE_CloseObject(token->db_hdl);
	token->db_hdl = TEE_HANDLE_NULL;
}

int update_persistent_db(struct ck_token *token, size_t offset, size_t size)
{
	unsigned int token_id = get_token_id(token);
	char file[] = TOKEN_DB_FILE_BASE;
	uint8_t *field = (uint8_t *)token->db_main + offset;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (snprintf(file + sizeof(file) - 2, 2, "%1d", token_id) >= 2)
		TEE_Panic(0);

	if (token->db_hdl == TEE_HANDLE_NULL)
		return 1;

	res = TEE_SeekObjectData(token->db_hdl, offset, TEE_DATA_SEEK_SET);
	if (res)
		return tee2sks_error(res);

	res = TEE_WriteObjectData(token->db_hdl, field, size);
	if (res)
		return tee2sks_error(res);

	return 0;
}

static void init_pin_keys(struct ck_token *token, unsigned int uid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int token_id = get_token_id(token);
	TEE_ObjectHandle *key_hdl = &token->pin_hdl[uid];
	char file[32] = { 0 };

	assert(token_id < 10 && uid < 10);

	if (snprintf(file, 32, "token.db.%1d-pin%1d", token_id, uid) >= 32)
		TEE_Panic(0);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					file, sizeof(file), 0, key_hdl);
	if (res == TEE_SUCCESS) {
		DMSG("PIN key found");
		return;
	}

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		TEE_Attribute attr;
		TEE_ObjectHandle hdl = TEE_HANDLE_NULL;
		uint8_t pin_key[16] = { 0 };

		TEE_MemFill(&attr, 0, sizeof(attr));

		TEE_GenerateRandom(pin_key, sizeof(pin_key));
		TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
				     pin_key, sizeof(pin_key));

		res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &hdl);
		if (res)
			TEE_Panic(0);

		res = TEE_PopulateTransientObject(hdl, &attr, 1);
		if (res)
			TEE_Panic(0);

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 file, sizeof(file), 0,
						 hdl,
						 pin_key, sizeof(pin_key),
						 key_hdl);
		if (res)
			TEE_Panic(0);

		TEE_FreeTransientObject(hdl);
		return;
	}

	TEE_Panic(0);
}

/* UUID for persistent object */
uint32_t create_object_uuid(struct ck_token *token __unused,
			    struct sks_object *obj)
{
	assert(!obj->uuid);

	obj->uuid = TEE_Malloc(sizeof(TEE_UUID),
				TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!obj->uuid)
		return SKS_MEMORY;

	TEE_GenerateRandom(obj->uuid, sizeof(TEE_UUID));

	/*
	 * TODO: check uuid against already registered one (in persistent
	 * database) and the pending created uuids (not already registered
	 * if any).
	 */
	return SKS_OK;
}

void destroy_object_uuid(struct ck_token *token __unused,
			 struct sks_object *obj)
{
	if (!obj->uuid)
		return;

	/* TODO: check uuid is not still registered in persistent db ? */
	TEE_Free(obj->uuid);
	obj->uuid = NULL;
}

uint32_t get_persistent_objects_list(struct ck_token *token,
				     TEE_UUID *array, size_t *size)
{
	size_t out_size = *size;

	*size = token->db_objs->count * sizeof(TEE_UUID);

	if (out_size < *size)
		return SKS_SHORT_BUFFER;

	if (array)
		TEE_MemMove(array, token->db_objs->uuids, *size);

	return SKS_OK;
}

uint32_t unregister_persistent_object(struct ck_token *token, TEE_UUID *uuid)
{
	int index = 0;
	int count = 0;
	struct token_persistent_objs *ptr;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!uuid)
		return SKS_OK;

	for (index = (int)(token->db_objs->count) - 1; index >= 0; index--) {
		if (!TEE_MemCompare(token->db_objs->uuids + index,
				    uuid, sizeof(TEE_UUID)))
			break;
	}

	if (index < 0) {
		EMSG("Cannot unregister an invalid persistent object");
		return SKS_NOT_FOUND;
	}

	ptr = TEE_Malloc(sizeof(struct token_persistent_objs) +
			 ((token->db_objs->count - 1) * sizeof(TEE_UUID)),
			 TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!ptr)
		return SKS_MEMORY;

	res = TEE_SeekObjectData(token->db_hdl,
				 sizeof(struct token_persistent_main),
				 TEE_DATA_SEEK_SET);
	if (res) {
		EMSG("Failed to read database");
		TEE_Free(ptr);
		return tee2sks_error(res);
	}

	TEE_MemMove(ptr, token->db_objs,
		    sizeof(struct token_persistent_objs) +
		    index * sizeof(TEE_UUID));

	ptr->count--;
	count = ptr->count - index;

	TEE_MemMove(&ptr->uuids[index],
		    &token->db_objs->uuids[index + 1],
		    count * sizeof(TEE_UUID));

	res = TEE_WriteObjectData(token->db_hdl, ptr,
				  sizeof(struct token_persistent_objs) +
				  ptr->count * sizeof(TEE_UUID));
	if (res) {
		EMSG("Failed to update database");
		TEE_Free(ptr);
		return tee2sks_error(res);
	}

	TEE_Free(token->db_objs);
	token->db_objs = ptr;

	return SKS_OK;
}

uint32_t register_persistent_object(struct ck_token *token, TEE_UUID *uuid)
{
	int count = 0;
	void *ptr = NULL;
	size_t __maybe_unused size = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	for (count = (int)token->db_objs->count - 1; count >= 0; count--)
		if (!TEE_MemCompare(token->db_objs->uuids + count, uuid,
				    sizeof(TEE_UUID)))
			TEE_Panic(0);

	count = token->db_objs->count;
	ptr = TEE_Realloc(token->db_objs,
			  sizeof(struct token_persistent_objs) +
			  ((count + 1) * sizeof(TEE_UUID)));
	if (!ptr)
		return SKS_MEMORY;

	token->db_objs = ptr;
	TEE_MemMove(token->db_objs->uuids + count, uuid, sizeof(TEE_UUID));

	size = sizeof(struct token_persistent_main) +
		sizeof(struct token_persistent_objs) +
		count * sizeof(TEE_UUID);

	res = TEE_TruncateObjectData(token->db_hdl, size + sizeof(TEE_UUID));
	if (res)
		return tee2sks_error(res);

	res = TEE_SeekObjectData(token->db_hdl,
				 sizeof(struct token_persistent_main),
				 TEE_DATA_SEEK_SET);
	if (res)
		return tee2sks_error(res);

	token->db_objs->count++;

	res = TEE_WriteObjectData(token->db_hdl, token->db_objs,
				  sizeof(struct token_persistent_objs) +
				  token->db_objs->count * sizeof(TEE_UUID));
	if (res) {
		token->db_objs->count--;
		return tee2sks_error(res);
	}

	return SKS_OK;
}

/*
 * Return the token instance, either initialized from reset or initialized
 * from the token persistent state if found.
 */
struct ck_token *init_token_db(unsigned int token_id)
{
	struct ck_token *token = get_token(token_id);
	TEE_Result res = TEE_ERROR_GENERIC;
	char db_file[] = TOKEN_DB_FILE_BASE;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;
	/* Copy persistent database: main db and object db */
	struct token_persistent_main *db_main = NULL;
	struct token_persistent_objs *db_objs = NULL;
	int n = 0;
	void *ptr = NULL;

	if (!token)
		return NULL;

	for (n = 0; n < SKS_MAX_USERS; n++)
		init_pin_keys(token, n);

	LIST_INIT(&token->object_list);

	db_main = TEE_Malloc(sizeof(*db_main), TEE_MALLOC_FILL_ZERO);
	db_objs = TEE_Malloc(sizeof(*db_objs), TEE_MALLOC_FILL_ZERO);
	if (!db_main || !db_objs)
		goto error;

	/* Persistent object ID is the string with last char replaced */
	if (snprintf(db_file + sizeof(db_file) - 2, 2, "%1d", token_id) >= 2)
		TEE_Panic(0);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					db_file, sizeof(db_file),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE,
					&db_hdl);
	if (res == TEE_SUCCESS) {
		uint32_t size = 0;
		size_t idx = 0;

		IMSG("SKSt%u: load db", token_id);

		size = sizeof(*db_main);
		res = TEE_ReadObjectData(db_hdl, db_main, size, &size);
		if (res || size != sizeof(*db_main))
			TEE_Panic(0);

		size = sizeof(*db_objs);
		res = TEE_ReadObjectData(db_hdl, db_objs, size, &size);
		if (res || size != sizeof(*db_objs))
			TEE_Panic(0);

		size += db_objs->count * sizeof(TEE_UUID);
		ptr = TEE_Realloc(db_objs, size);
		if (!ptr)
			goto error;

		db_objs = ptr;
		size -= sizeof(struct token_persistent_objs);
		res = TEE_ReadObjectData(db_hdl, db_objs->uuids, size, &size);
		if (res || size != (db_objs->count * sizeof(TEE_UUID)))
			TEE_Panic(0);

		for (idx = 0; idx < db_objs->count; idx++) {
			/* Create an empty object instance */
			struct sks_object *obj = NULL;
			TEE_UUID *uuid = NULL;

			uuid = TEE_Malloc(sizeof(TEE_UUID),
					  TEE_USER_MEM_HINT_NO_FILL_ZERO);
			if (!uuid)
				goto error;

			TEE_MemMove(uuid, &db_objs->uuids[idx], sizeof(*uuid));

			obj = create_token_object_instance(NULL, uuid);
			if (!obj)
				TEE_Panic(0);

			LIST_INSERT_HEAD(&token->object_list, obj, link);
		}

	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {

		IMSG("SKSt%u: init db", token_id);

		TEE_MemFill(db_main, 0, sizeof(*db_main));
		TEE_MemFill(db_main->label, '*', sizeof(db_main->label));

		/*
		 * Not supported:
		 *   SKS_TOKEN_FULLY_RESTORABLE
		 * TODO: check these:
		 *   SKS_TOKEN_HAS_CLOCK => related to TEE time secure level
		 */
		db_main->flags = SKS_CKFT_SO_PIN_TO_BE_CHANGED |
				 SKS_CKFT_USER_PIN_TO_BE_CHANGED |
				 SKS_CKFT_RNG |
				 SKS_CKFT_DUAL_CRYPTO_OPERATIONS |
				 SKS_CKFT_LOGIN_REQUIRED;

		/* 2 files: persistent state + persistent object references */
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 db_file, sizeof(db_file),
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE,
						 TEE_HANDLE_NULL,
						 db_main, sizeof(*db_main),
						 &db_hdl);
		if (res)
			TEE_Panic(0);

		res = TEE_TruncateObjectData(db_hdl, sizeof(*db_main) +
							sizeof(*db_objs));
		if (res)
			TEE_Panic(0);

		res = TEE_SeekObjectData(db_hdl, sizeof(*db_main),
					 TEE_DATA_SEEK_SET);
		if (res)
			TEE_Panic(0);

		db_objs->count = 0;
		res = TEE_WriteObjectData(db_hdl, db_objs, sizeof(*db_objs));
		if (res)
			TEE_Panic(0);

	} else {
		/* Can't do anything... */
		return NULL;
	}

	token->db_main = db_main;
	token->db_objs = db_objs;
	token->db_hdl = db_hdl;
	TEE_SeekObjectData(token->db_hdl, 0, TEE_DATA_SEEK_SET);

	return token;

error:
	TEE_Free(db_main);
	TEE_Free(db_objs);
	if (db_hdl != TEE_HANDLE_NULL)
		TEE_CloseObject(db_hdl);

	return NULL;
}
