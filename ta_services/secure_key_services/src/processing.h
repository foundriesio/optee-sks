/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#ifndef __SKS_PROCESSING_H__
#define __SKS_PROCESSING_H__

#include <tee_internal_api.h>

struct pkcs11_session;
struct sks_object;

/*
 * Entry points frpom SKS TA invocation commands
 */

uint32_t entry_import_object(uintptr_t teesess, TEE_Param *ctrl,
			     TEE_Param *in, TEE_Param *out);

uint32_t entry_generate_secret(uintptr_t teesess,
			       TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);


uint32_t entry_processing_init(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out,
				enum processing_func function);

uint32_t entry_processing_step(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out,
				enum processing_func function,
				enum processing_step step);

/* verify_oneshot is specific since it get 2 input data buffers */
uint32_t entry_verify_oneshot(uintptr_t tee_session, TEE_Param *ctrl,
				  TEE_Param *in1, TEE_Param *in2,
				  enum processing_func function,
				  enum processing_step step);

/*
 * Util
 */
size_t get_object_key_bit_size(struct sks_object *obj);

/*
 * Symmetric crypto algorithm specific functions
 */
bool processing_is_tee_symm(uint32_t proc_id);

uint32_t init_symm_operation(struct pkcs11_session *session,
				enum processing_func function,
				struct sks_attribute_head *proc_params,
				struct sks_object *key);

uint32_t step_symm_operation(struct pkcs11_session *session,
				enum processing_func function,
				enum processing_step step,
				TEE_Param *io1, TEE_Param *io2);

void tee_release_ctr_operation(struct pkcs11_session *session);
uint32_t tee_init_ctr_operation(struct pkcs11_session *session,
				    void *proc_params, size_t params_size);

uint32_t tee_ae_decrypt_update(struct pkcs11_session *session,
			       void *in, size_t in_size);

uint32_t tee_ae_decrypt_final(struct pkcs11_session *session,
			      void *out, uint32_t *out_size);

uint32_t tee_ae_encrypt_final(struct pkcs11_session *session,
			      void *out, uint32_t *out_size);

void tee_release_ccm_operation(struct pkcs11_session *session);
uint32_t tee_init_ccm_operation(struct pkcs11_session *session,
				    void *proc_params, size_t params_size);

void tee_release_gcm_operation(struct pkcs11_session *session);
uint32_t tee_init_gcm_operation(struct pkcs11_session *session,
				    void *proc_params, size_t params_size);

#endif /*__SKS_PROCESSING_H__*/
