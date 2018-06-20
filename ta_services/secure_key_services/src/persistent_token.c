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
	int n;

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
	TEE_Result res;

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
	TEE_Result res;
	unsigned int token_id = get_token_id(token);
	TEE_ObjectHandle *key_hdl = &token->pin_hdl[uid];
	char file[32] = { 0 };

	assert(token_id < 10 && uid < 10);

	if (snprintf(file, 32, "token.db.%1d-pin%1d", token_id, uid) >= 32)
		TEE_Panic(0);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					file, sizeof(file), 0, key_hdl);
	if (res == TEE_SUCCESS) {
		MSG("pin key found");
		return;
	}

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		TEE_Attribute attr;
		TEE_ObjectHandle hdl = TEE_HANDLE_NULL;
		uint8_t pin_key[16];

		TEE_GenerateRandom(pin_key, sizeof(pin_key));
		TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
				     pin_key, sizeof(pin_key));

		res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, key_hdl);
		if (res)
			TEE_Panic(0);

		res = TEE_PopulateTransientObject(*key_hdl, &attr, 1);
		if (res)
			TEE_Panic(0);

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 file, sizeof(file), 0,
						 *key_hdl,
						 pin_key, sizeof(pin_key),
						 &hdl);
		if (res)
			TEE_Panic(0);

		TEE_CloseObject(hdl);
		return;
	}

	TEE_Panic(0);
}

/* UUID for persistent object */
uint32_t create_object_uuid(struct ck_token *token __unused,
			    struct sks_object *obj)
{
	assert(!obj->uuid);

	obj->uuid = TEE_Malloc(sizeof(TEE_UUID), 0);
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
	int index;
	int count;
	void *ptr;
	TEE_Result res;

	if (!uuid)
		return SKS_OK;

	for (index = (int)(token->db_objs->count) - 1; index >= 0; index--) {
		if (!TEE_MemCompare(token->db_objs->uuids + index,
				    uuid, sizeof(TEE_UUID)))
			break;
	}

	if (index < 0) {
		EMSG("Cannot unregster an invalid persistent object");
		return SKS_NOT_FOUND;
	}

	count = token->db_objs->count - index;

	res = TEE_SeekObjectData(token->db_hdl,
				 sizeof(struct token_persistent_main) +
				 sizeof(struct token_persistent_objs) +
				 index * sizeof(TEE_UUID),
				 TEE_DATA_SEEK_SET);
	if (res) {
		EMSG("Failed to read db");
		tee2sks_error(res);
	}

	res = TEE_WriteObjectData(token->db_hdl,
				  token->db_objs->uuids + index + 1,
				  (count - 1) * sizeof(TEE_UUID));
	if (res) {
		EMSG("Failed to update db");
		tee2sks_error(res);
	}

	/* Below sequence must not fail as persistent database is updated */

	TEE_MemMove(token->db_objs->uuids + index,
		    token->db_objs->uuids + index + 1,
		    (count - 1) * sizeof(TEE_UUID));

	/* Now we can decrease the uuid counter */
	token->db_objs->count--;

	ptr = TEE_Realloc(token->db_objs,
			  sizeof(struct token_persistent_objs) +
			  (token->db_objs->count * sizeof(TEE_UUID)));

	/* If realloc fails, just keep current buffer */
	if (ptr)
		token->db_objs = ptr;

	return SKS_OK;
}

uint32_t register_persistent_object(struct ck_token *token, TEE_UUID *uuid)
{
	int count;
	void *ptr;
	size_t size __maybe_unused;
	TEE_Result res = 0;

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
		(count * sizeof(TEE_UUID));

	res = TEE_TruncateObjectData(token->db_hdl, size + sizeof(TEE_UUID));
	if (res)
		return tee2sks_error(res);

	res = TEE_SeekObjectData(token->db_hdl, size, TEE_DATA_SEEK_SET);
	if (res)
		return tee2sks_error(res);

	res = TEE_WriteObjectData(token->db_hdl, token->db_objs->uuids + count,
				  sizeof(TEE_UUID));
	if (res)
		return tee2sks_error(res);

	/* Now we can increase the uuid counter */
	token->db_objs->count++;

	return SKS_OK;
}

/*
 * Return the token instance, either initialized from reset or initialized
 * from the token persistent state if found.
 */
struct ck_token *init_token_db(unsigned int token_id)
{
	struct ck_token *token = get_token(token_id);
	TEE_Result res;
	char db_file[] = TOKEN_DB_FILE_BASE;
	TEE_ObjectHandle db_hdl = TEE_HANDLE_NULL;
	struct token_persistent_main *db_main;	/* Copy persistent database */
	struct token_persistent_objs *db_objs;	/* Copy persistent database */
	int n;

	if (!token)
		return NULL;

	for (n = 0; n < SKS_MAX_USERS; n++)
		init_pin_keys(token, n);

	db_main = TEE_Malloc(sizeof(*db_main), 0);
	db_objs = TEE_Malloc(sizeof(*db_objs), 0);
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
		uint32_t size;

		size = sizeof(*db_main);
		res = TEE_ReadObjectData(db_hdl, db_main, size, &size);
		if (res || size != sizeof(*db_main))
			TEE_Panic(0);

		size = sizeof(*db_objs);
		res = TEE_ReadObjectData(db_hdl, db_objs, size, &size);
		if (res || size != sizeof(*db_objs))
			TEE_Panic(0);

		size += db_objs->count * sizeof(TEE_UUID);
		db_objs = TEE_Realloc(db_objs, size);
		if (!db_objs)
			goto error;

		size -= sizeof(*db_objs);
		res = TEE_ReadObjectData(db_hdl, db_objs, size, &size);
		if (res || size != (db_objs->count * sizeof(TEE_UUID)))
			TEE_Panic(0);

	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {

		IMSG("Init SKS persistent database for token #%d", token_id);

		TEE_MemFill(db_main, 0, sizeof(*db_main));
		TEE_MemFill(db_main->label, '*', sizeof(db_main->label));

		/*
		 * Not supported:
		 *   SKS_TOKEN_FULLY_RESTORABLE
		 * TODO: check these:
		 *   SKS_TOKEN_HAS_CLOCK => related to TEE time secure level
		 */
		db_main->flags = SKS_TOKEN_SO_PIN_TO_CHANGE | \
				 SKS_TOKEN_USR_PIN_TO_CHANGE | \
				 SKS_TOKEN_HAS_RNG | \
				 SKS_TOKEN_IS_READ_ONLY | \
				 SKS_TOKEN_REQUIRE_LOGIN | \
				 SKS_TOKEN_CAN_DUAL_PROC;

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
