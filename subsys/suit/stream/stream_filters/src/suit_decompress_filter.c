/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <nrf_compress/implementation.h>
#include <suit_decompress_filter.h>
#include <suit_types.h>
#include <suit_plat_decode_util.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(suit_decompress_filter, CONFIG_SUIT_LOG_LEVEL);

struct decompress_ctx {
	struct stream_sink out_sink;
	bool in_use;
	nrf_compress_implementation *codec_impl;
	void *codec_ctx;
	uint8_t last_chunk[2 * LZMA_REQUIRED_INPUT_MAX];
	uint8_t last_chunk_size;
};

static struct decompress_ctx ctx;

/**
 * @brief Interface functions for external lzma dictionary
 */
static int open_dictionary(size_t dict_size, size_t *buff_size);
static int close_dictionary(void);
static size_t write_dictionary(size_t pos, const uint8_t *data, size_t len);
static size_t read_dictionary(size_t pos, uint8_t *data, size_t len);

static const lzma_dictionary_interface lzma_if {
	.open = open_dictionary,
	.close = close_dictionary,
	.write = write_dictionary,
	.read = read_dictionary
};

static const lzma_codec lzma_inst = {
	.dict_if = lzma_if
};

/*
 * Use pointer to volatile function, as stated in Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * Although some compilers may still optimize out the memset, it is safer to use
 * some sort of trick than simply call memset.
 */
static void *(*const volatile memset_func)(void *, int, size_t) = memset;

static void zeroize(void *buf, size_t len)
{
	if ((buf == NULL) || (len == 0)) {
		return;
	}

	memset_func(buf, 0, len);
}

static suit_plat_err_t erase(void *ctx)
{
	suit_plat_err_t res = SUIT_PLAT_SUCCESS;

	if (ctx != NULL) {
		struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;

		if (decompress_ctx->out_sink.erase != NULL) {
			res = decompress_ctx->out_sink.erase(decompress_ctx->out_sink.ctx);
		}
	} else {
		res = SUIT_PLAT_ERR_INVAL;
	}

	return res;
}

static suit_plat_err_t write(void *ctx, const uint8_t *buf, size_t size)
{
	suit_plat_err_t err = SUIT_PLAT_SUCCESS;
	size_t chunk_size;
	int rc;
	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;
	uint8_t *output = NULL;
    size_t output_size = 0;
	uint32_t processed_size = 0;
	uint8_t first_chunk[2 * LZMA_REQUIRED_INPUT_MAX];

	if ((ctx == NULL) || (buf == NULL) || (size == 0)) {
		LOG_ERR("Invalid arguments.");
		return SUIT_PLAT_ERR_INVAL;
	}

	if (!decompress_ctx->in_use) {
		LOG_ERR("Decrypt filter not initialized.");
		return SUIT_PLAT_ERR_INVAL;
	}

	nrf_compress_implementation *codec_impl;
	codec_impl = decompress_ctx->codec_impl;

	memcpy(first_chunk, decompress_ctx->last_chunk, decompress_ctx->last_chunk_size);

	while (size - LZMA_REQUIRED_INPUT_MAX > 0) {
		chunk_size = MIN(size,
			codec_impl->decompress_bytes_needed(decompress_ctx->codec_ctx));

		rc = codec_impl->decompress(decompress_ctx->codec_ctx,
						buf, chunk_size, false,
						&processed_size, &output, &output_size);

		if (output_size != 0) {
			/** It means that we reached the end of dictionary buffer,
			 * which must not happen in our case - we cannot override
			 * it as it occupies image space.
			 */
			LOG_ERR("Too big decompressed image size: %u", output_size);
			err = SUIT_PLAT_ERR_CRASH;
			goto cleanup;
		}

		if (decrypted_len == 0) {
			/* The remaining data will be decrypted by the flush function */
			goto cleanup;
		}

		err = decompress_ctx->out_sink.write(decompress_ctx->out_sink.ctx, decrypted_buf,
						  decrypted_len);

		if (err != SUIT_PLAT_SUCCESS) {
			LOG_ERR("Failed to write decrypted data: %d", err);
			goto cleanup;
		}

		size -= chunk_size;
		buf += chunk_size;
	}

cleanup:
	/* Clear the RAM buffer so that no decrypted data is stored in unwanted places */
	zeroize(decrypted_buf, sizeof(decrypted_buf));

	return err;
}

static suit_plat_err_t flush(void *ctx)
{
	suit_plat_err_t res = SUIT_PLAT_SUCCESS;
	psa_status_t status = PSA_SUCCESS;

	uint8_t decrypted_buf[PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE] = {0};
	size_t decrypted_len = 0;
	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;
	psa_key_id_t cek_key_id_value = 0;

	if (ctx == NULL) {
		LOG_ERR("Invalid arguments - decrypt ctx is NULL");
		return SUIT_PLAT_ERR_INVAL;
	}

#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
	cek_key_id_value = decompress_ctx->cek_key_id.MBEDTLS_PRIVATE(key_id);
#else
	cek_key_id_value = decompress_ctx->cek_key_id;
#endif
	if (cek_key_id_value == 0) {
		LOG_DBG("Filter already flushed");
		return SUIT_PLAT_SUCCESS;
	}

	if (decompress_ctx->stored_tag_bytes < decompress_ctx->tag_size) {
		LOG_ERR("Tag not fully stored.");

		psa_aead_abort(&decompress_ctx->operation);
		res = SUIT_PLAT_ERR_INCORRECT_STATE;
	}

	if (res == SUIT_PLAT_SUCCESS) {
		status = psa_aead_verify(&decompress_ctx->operation, decrypted_buf,
					 sizeof(decrypted_buf), &decrypted_len, decompress_ctx->tag,
					 decompress_ctx->tag_size);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to verify tag/finish decryption: %d.", status);
			/* Revert all the changes so that no decrypted data remains */
			erase(decompress_ctx);
			psa_aead_abort(&decompress_ctx->operation);
			res = SUIT_PLAT_ERR_AUTHENTICATION;
		} else {
			LOG_INF("Firmware decryption successful");

			/* Using out_sink without a write API is blocked by the filter constructor.
			 */
			if (decrypted_len > 0) {
				res = decompress_ctx->out_sink.write(decompress_ctx->out_sink.ctx,
								  decrypted_buf, decrypted_len);
				if (res != SUIT_PLAT_SUCCESS) {
					LOG_ERR("Failed to write decrypted data: %d", res);
					/* Revert all the changes so that
					 * no decrypted data remains
					 */
					erase(decompress_ctx);
				}
			}
		}
	}

#ifdef CONFIG_SUIT_AES_KW_MANUAL
	if (decompress_ctx->kw_alg_id == suit_cose_aes256_kw) {
		psa_destroy_key(decompress_ctx->cek_key_id);
	}
#endif

	zeroize(decrypted_buf, sizeof(decrypted_buf));

	memset(&decompress_ctx->cek_key_id, 0, sizeof(decompress_ctx->cek_key_id));
	zeroize(&decompress_ctx->operation, sizeof(decompress_ctx->operation));
	decompress_ctx->tag_size = 0;
	decompress_ctx->stored_tag_bytes = 0;
	zeroize(decompress_ctx->tag, sizeof(decompress_ctx->tag));
	decompress_ctx->kw_alg_id = 0;

	return res;
}

static suit_plat_err_t release(void *ctx)
{
	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;

	if (ctx == NULL) {
		LOG_ERR("Invalid arguments - decrypt ctx is NULL");
		return SUIT_PLAT_ERR_INVAL;
	}

	suit_plat_err_t res = flush(ctx);

	if (decompress_ctx->out_sink.release != NULL) {
		suit_plat_err_t release_ret =
			decompress_ctx->out_sink.release(decompress_ctx->out_sink.ctx);

		if (res == SUIT_SUCCESS) {
			res = release_ret;
		}
	}

	zeroize(&decompress_ctx->out_sink, sizeof(struct stream_sink));

	decompress_ctx->in_use = false;

	return res;
}

static suit_plat_err_t used_storage(void *ctx, size_t *size)
{
	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;

	if ((ctx == NULL) || (size == NULL)) {
		LOG_ERR("Invalid arguments.");
		return SUIT_PLAT_ERR_INVAL;
	}

	if (decompress_ctx->out_sink.used_storage != NULL) {
		return decompress_ctx->out_sink.used_storage(decompress_ctx->out_sink.ctx, size);
	}

	return SUIT_PLAT_ERR_UNSUPPORTED;
}

static suit_plat_err_t validate_decompression(const struct suit_compression_info *compress_info,
						   const suit_manifest_class_id_t *class_id,
						   nrf_compress_types *compress_type)
{
	switch(compress_info->compression_alg_id)
	{
		case suit_lzma2:
			/** Perform the validation of class_id ?*/
			compress_type = NRF_COMPRESS_TYPE_LZMA;
			ctx.codec_ctx = &lzma_inst;
			break;
		default:
			LOG_ERR("Unsupported decompression algorithm: %d",
				compress_info->compression_alg_id);
			return SUIT_PLAT_ERR_INVAL;
	}
	return SUIT_PLAT_SUCCESS;
}

suit_plat_err_t suit_decompress_filter_get(struct stream_sink *in_sink,
					const struct suit_compression_info *compress_info,
					const suit_manifest_class_id_t *class_id,
					const struct stream_sink *out_sink)
{
	int rc;
	suit_plat_err_t ret = SUIT_PLAT_SUCCESS;

	if (ctx.in_use) {
		LOG_ERR("The decompression filter is busy");
		return SUIT_PLAT_ERR_BUSY;
	}

	if ((compress_info == NULL) || (out_sink == NULL) || (in_sink == NULL) ||
	    (out_sink->write == NULL) || class_id == NULL) {
		return SUIT_PLAT_ERR_INVAL;
	}

	ctx.in_use = true;

	enum nrf_compress_types compress_type;

	ret = validate_decompression(compress_info, class_id, &compress_type);

	if (ret != SUIT_PLAT_SUCCESS) {
		ctx.in_use = false;
		return ret;
	}

	ctx.codec_impl = nrf_compress_implementation_find(compress_type);

	if (ctx.codec_impl == NULL) {
		ctx.in_use = false;
		LOG_ERR("Could not find codec implementation for selected compression type");
		return SUIT_PLAT_ERR_CRASH;
	}

	rc = codec_impl->init(ctx.codec_ctx);

	if (rc != 0) {
		LOG_ERR("Failed to initialize lzma codec");
		ctx.in_use = false
		ctx.codec_impl = NULL;
		ctx.codec_ctx = NULL;
		return SUIT_PLAT_ERR_CRASH;
	}

	memcpy(&ctx.out_sink, out_sink, sizeof(struct stream_sink));

	in_sink->ctx = &ctx;

	in_sink->write = write;
	in_sink->erase = erase;
	in_sink->release = release;
	in_sink->flush = flush;

	if (out_sink->used_storage != NULL) {
		in_sink->used_storage = used_storage;
	} else {
		in_sink->used_storage = NULL;
	}

	/* Seeking is not possible on compressed payload. */
	in_sink->seek = NULL;

	return SUIT_PLAT_SUCCESS;
}
