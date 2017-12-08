/*
 * Copyright (c) 2017, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __CRYPTO_AES_CCM_H
#define __CRYPTO_AES_CCM_H

#include <tee_api_types.h>

size_t crypto_aes_ccm_get_ctx_size(void);
TEE_Result crypto_aes_ccm_init(void *ctx, TEE_OperationMode mode,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *nonce, size_t nonce_len,
			       size_t tag_len, size_t aad_len,
			       size_t payload_len);
TEE_Result crypto_aes_ccm_update_aad(void *ctx, const uint8_t *data,
				     size_t len);
TEE_Result crypto_aes_ccm_update_payload(void *ctx, TEE_OperationMode mode,
					 const uint8_t *src_data,
					 size_t len, uint8_t *dst_data);
TEE_Result crypto_aes_ccm_enc_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    uint8_t *dst_tag, size_t *dst_tag_len);
TEE_Result crypto_aes_ccm_dec_final(void *ctx, const uint8_t *src_data,
				    size_t len, uint8_t *dst_data,
				    const uint8_t *tag, size_t tag_len);
void crypto_aes_ccm_final(void *ctx);

#endif /*__CRYPTO_AES_CCM_H*/

