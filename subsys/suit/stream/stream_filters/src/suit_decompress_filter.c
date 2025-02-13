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

#define CHUNK_BUFFER_SIZE 20 // the same as LZMA_REQUIRED_INPUT_MAX

struct decompress_ctx {
	const struct stream_sink *out_sink;
	bool in_use;
	const struct nrf_compress_implementation *codec_impl;
	const void *codec_ctx;
	uint8_t last_chunk[CHUNK_BUFFER_SIZE];
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

static const lzma_dictionary_interface lzma_if = {
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

static int open_dictionary(size_t dict_size, size_t *buff_size)
{
	LOG_ERR("Opening dictionary with requested size: %d", dict_size);
	return 0;
}
static int close_dictionary(void)
{
	return 0;
}
static size_t write_dictionary(size_t pos, const uint8_t *data, size_t len)
{
	return len;
}
static size_t read_dictionary(size_t pos, uint8_t *data, size_t len)
{
	return len;
}

static suit_plat_err_t erase(void *ctx)
{
	suit_plat_err_t res = SUIT_PLAT_SUCCESS;

	if (ctx != NULL) {
		struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;

		if (decompress_ctx->out_sink->erase != NULL) {
			LOG_ERR("WTF2");
			res = decompress_ctx->out_sink->erase(decompress_ctx->out_sink->ctx);
		}
	} else {
		res = SUIT_PLAT_ERR_INVAL;
	}

	return res;
}

static suit_plat_err_t write(void *ctx, const uint8_t *buf, size_t size)
{
	suit_plat_err_t res = SUIT_PLAT_SUCCESS;
	size_t chunk_size;
	int rc;
	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;
	uint8_t *output = NULL;
    size_t output_size = 0;
	uint32_t processed_size = 0;
	const struct nrf_compress_implementation *codec_impl;

	if ((ctx == NULL) || (buf == NULL) || (size == 0)) {
		LOG_ERR("Invalid arguments.");
		return SUIT_PLAT_ERR_INVAL;
	}

	if (!decompress_ctx->in_use) {
		LOG_ERR("Decrypt filter not initialized.");
		return SUIT_PLAT_ERR_INVAL;
	}

	codec_impl = decompress_ctx->codec_impl;

	while (size + decompress_ctx->last_chunk_size > CHUNK_BUFFER_SIZE) {
		/* Make sure we buffer CHUNK_BUFFER_SIZE bytes
		 * in ctx.last_chunk for the flush operation. */

		if (decompress_ctx->last_chunk_size >= CHUNK_BUFFER_SIZE) {

			chunk_size = MIN(CHUNK_BUFFER_SIZE, size);

			rc = codec_impl->decompress((void *)decompress_ctx->codec_ctx,
					decompress_ctx->last_chunk, chunk_size,
					false, &processed_size, &output, &output_size);

			if (rc != 0) {
				LOG_ERR("Decompression data error");
				res = SUIT_PLAT_ERR_CRASH;
				goto cleanup;
			}

			if (output_size != 0
			   || processed_size != chunk_size) {
				/* It means that we reached the end of dictionary buffer,
				 * which must not happen in our case - we cannot override
				 * it as it occupies image space.
				 */
				LOG_ERR("Too big decompressed image size");
				res = SUIT_PLAT_ERR_CRASH;
				goto cleanup;
			}

			decompress_ctx->last_chunk_size -= chunk_size;
			continue;
		}

		chunk_size = MIN(size - CHUNK_BUFFER_SIZE,
			codec_impl->decompress_bytes_needed((void *)decompress_ctx->codec_ctx));

		rc = codec_impl->decompress((void *)decompress_ctx->codec_ctx,
						buf, chunk_size, false,
						&processed_size, &output, &output_size);

		if (rc != 0) {
			LOG_ERR("Decompression data error");
			res = SUIT_PLAT_ERR_CRASH;
			goto cleanup;
		}

		if (output_size != 0 || processed_size != chunk_size) {
			/** It means that we reached the end of dictionary buffer,
			 * which must not happen in our case - we cannot override
			 * it as it occupies image space.
			 */
			LOG_ERR("Too big decompressed image size");
			res = SUIT_PLAT_ERR_CRASH;
			goto cleanup;
		}

		size -= processed_size;
		buf += processed_size;
	}

	memcpy(decompress_ctx->last_chunk + decompress_ctx->last_chunk_size, buf, size);
	decompress_ctx->last_chunk_size += size;
	return res;

cleanup:
	/* Clear the RAM buffer so that no image data is stored in unwanted places */
	zeroize(decompress_ctx->last_chunk, sizeof(decompress_ctx->last_chunk));

	return res;
}

static suit_plat_err_t flush(void *ctx)
{
	suit_plat_err_t res = SUIT_PLAT_SUCCESS;
	size_t chunk_size;
	int rc;
	uint8_t *output = NULL;
    size_t output_size = 0;
	uint32_t processed_size = 0;
	const struct nrf_compress_implementation *codec_impl;

	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;

	codec_impl = decompress_ctx->codec_impl;

	if (ctx == NULL) {
		LOG_ERR("Invalid arguments - decompress ctx is NULL");
		return SUIT_PLAT_ERR_INVAL;
	}

	if (!decompress_ctx->in_use) {
		LOG_ERR("Decompress filter not initialized.");
		return SUIT_PLAT_ERR_INVAL;
	}

	if (decompress_ctx->last_chunk_size == 0) {
		LOG_WRN("Wrong decompression state.");
		res = SUIT_PLAT_ERR_INCORRECT_STATE;
	}

	while (decompress_ctx->last_chunk_size > 0) {
		chunk_size = MIN(decompress_ctx->last_chunk_size,
			codec_impl->decompress_bytes_needed((void *)decompress_ctx->codec_ctx));

		rc = codec_impl->decompress((void *)decompress_ctx->codec_ctx,
						decompress_ctx->last_chunk, chunk_size, true,
						&processed_size, &output, &output_size);

		if (rc != 0) {
			LOG_ERR("Decompression data error");
			res = SUIT_PLAT_ERR_CRASH;
			break;
		}

		if (processed_size != chunk_size) {
			/** It means that we reached the end of dictionary buffer,
			 * which must not happen in our case - we cannot override
			 * it as it occupies image space.
			 */
			LOG_ERR("Too big decompressed image size");
			res = SUIT_PLAT_ERR_CRASH;
			break;
		}
		decompress_ctx->last_chunk_size -= processed_size;
	}

	if (res == 0) {
		LOG_INF("Firmware decompression successful");
	} else {
		erase(decompress_ctx);
	}

	LOG_ERR("WTF");
	rc = codec_impl->reset((void *)decompress_ctx->codec_ctx);
	zeroize(decompress_ctx->last_chunk, sizeof(decompress_ctx->last_chunk));

	return res;
}

static suit_plat_err_t release(void *ctx)
{
	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;
	const struct nrf_compress_implementation *codec_impl;

	if (ctx == NULL) {
		LOG_ERR("Invalid arguments - decompress ctx is NULL");
		return SUIT_PLAT_ERR_INVAL;
	}

	codec_impl = decompress_ctx->codec_impl;

	suit_plat_err_t res = flush(ctx);

	if (decompress_ctx->out_sink->release != NULL) {
		suit_plat_err_t release_ret =
			decompress_ctx->out_sink->release(decompress_ctx->out_sink->ctx);

		if (res == SUIT_SUCCESS) {
			res = release_ret;
		}
	}

	codec_impl->deinit((void *)decompress_ctx->codec_ctx);
	zeroize(decompress_ctx, sizeof(struct decompress_ctx));

	return res;
}

static suit_plat_err_t used_storage(void *ctx, size_t *size)
{
	struct decompress_ctx *decompress_ctx = (struct decompress_ctx *)ctx;

	if ((ctx == NULL) || (size == NULL)) {
		LOG_ERR("Invalid arguments.");
		return SUIT_PLAT_ERR_INVAL;
	}

	if (decompress_ctx->out_sink->used_storage != NULL) {
		return decompress_ctx->out_sink->used_storage(decompress_ctx->out_sink->ctx, size);
	}

	return SUIT_PLAT_ERR_UNSUPPORTED;
}

static suit_plat_err_t validate_decompression(const struct suit_compression_info *compress_info,
						   const suit_manifest_class_id_t *class_id,
						   enum nrf_compress_types *compress_type)
{
	switch(compress_info->compression_alg_id)
	{
		case suit_lzma2:
			/** Perform the validation of class_id ?*/
			*compress_type = NRF_COMPRESS_TYPE_LZMA;
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

	enum nrf_compress_types compress_type = NRF_COMPRESS_TYPE_COUNT;

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

	rc = ctx.codec_impl->init((void *)ctx.codec_ctx);

	if (rc != 0) {
		LOG_ERR("Failed to initialize lzma codec");
		ctx.in_use = false;
		ctx.codec_impl = NULL;
		ctx.codec_ctx = NULL;
		return SUIT_PLAT_ERR_CRASH;
	}

	ctx.out_sink = out_sink;
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
