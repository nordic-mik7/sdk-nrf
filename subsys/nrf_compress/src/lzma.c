/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdint.h>
#include <stdlib.h>
#include <LzmaDec.h>
#include <Lzma2Dec.h>
#include <nrf_compress/implementation.h>
#include <nrf_compress/lzma_types.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(nrf_compress_lzma, CONFIG_NRF_COMPRESS_LOG_LEVEL);

/* Header size for lzma2 */
#define LZMA2_HEADER_SIZE 2

/* Assume lp and lc parameters in the compressed images do not sum to a value greater than the
 * following constant to limit the memory used by LZMA probability array.
 */
#define MAX_LZMA_LC_PLUS_LP 4
#define MAX_LZMA_PROB_SIZE  (1984 + (0x300 << MAX_LZMA_LC_PLUS_LP))

/* Assume the maximum LZMA dictionary size to limit the RAM buffer size for the decompressed
 * stream.
 */
#define MAX_LZMA_DICT_SIZE  (128 * 1024)

#if !defined(CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA1) && \
	!defined(CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2)
#error "Missing selection of lzma algorithm selection, please select " \
	"CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA1 or CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2"
#endif

#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_STATIC)
static uint16_t lzma_probs[MAX_LZMA_PROB_SIZE];
#endif

#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_MALLOC) && defined(CONFIG_NRF_COMPRESS_CLEANUP)
static size_t malloc_probs_size = 0;
#endif

static void *lzma_probs_alloc(ISzAllocPtr p, size_t size)
{
#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_STATIC)
	if (size > sizeof(lzma_probs)) {
		LOG_ERR("Compress library tried to allocate too large a buffer (0x%x)", size);
		return NULL;
	}

	return lzma_probs;
#else
	void *buffer = malloc(size);

	if (buffer == NULL) {
		LOG_ERR("Failed to allocate nRF compression library buffer (0x%x)", size);
#ifdef CONFIG_NRF_COMPRESS_CLEANUP
	} else {
		malloc_probs_size = size;
#endif
	}

	return buffer;
#endif
}

#ifdef CONFIG_NRF_COMPRESS_CLEANUP
/* Replacement for memset(p, 0, sizeof(*p) that does not get
 * optimized out.
 */
static void like_mbedtls_zeroize(void *p, size_t n)
{
	volatile unsigned char *v = (unsigned char *)p;

	for (size_t i = 0; i < n; i++) {
		v[i] = 0;
	}
}
#endif

static void lzma_probs_free(ISzAllocPtr p, void *address)
{
#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_MALLOC)
#ifdef CONFIG_NRF_COMPRESS_CLEANUP
	if (address == NULL) {
		return;
	}

	if (malloc_probs_size > 0) {
		like_mbedtls_zeroize(address, malloc_probs_size);
		malloc_probs_size = 0;
	}

#endif
	free(address);
#else
#ifdef CONFIG_NRF_COMPRESS_CLEANUP
	like_mbedtls_zeroize(lzma_probs, sizeof(lzma_probs));
#endif
#endif
}

const static ISzAlloc lzma_probs_allocator = {
	.Alloc = lzma_probs_alloc,
	.Free = lzma_probs_free,
};

#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_STATIC) \
	&& !defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
#if CONFIG_NRF_COMPRESS_MEMORY_ALIGNMENT > 1
static uint8_t __aligned(CONFIG_NRF_COMPRESS_MEMORY_ALIGNMENT) lzma_dict[MAX_LZMA_DICT_SIZE];
#else
static uint8_t lzma_dict[MAX_LZMA_DICT_SIZE];
#endif
#elif defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_MALLOC) \
	&& !defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
static uint8_t *lzma_dict = NULL;
#else

/* defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY) */

/**
 * @brief Pointer to external dictionary interface,
 * set on module initialization function and held as context variable.
 */
const lzma_dictionary_interface *ext_dict;

#if CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE > 0
/**
 * @brief Dictionary Cache Structure
 */
typedef struct dict_cache_t {
	/** Cached dictionary data. */
	uint8_t data[CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE];
	/** Indicates which dictionary element is stored as first element of @a data. */
	SizeT dict_pos_begin;
	/** Indicates which dictionary element is stored as last element of @a data. */
	SizeT dict_pos_end;
	/** Write offset, for keeping track on invalidated bytes. */
	SizeT write_offset;
	/** Cache invalidation flag - if set, it is out of sync with external dictionary. */
	bool invalid;
} dict_cache;

static dict_cache cache;
#endif
#endif

static bool allocated_probs = false;
#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
static CLzma2Dec lzma_decoder;
#else
static CLzmaDec lzma_decoder;
#endif

#if CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE > 0
/**
 * @brief Validate dictionary cache.
 *
 * This function synchronizes data in cache with external dictionary.
 *
 * @param handle pointer to Lzma dictionary handle struct, for dictionary size reference.
 *
 */
static void validate_cache(const DictHandle *handle)
{
	SizeT const dict_write_size = cache.write_offset;

	ext_dict->write(cache.dict_pos_begin, cache.data, dict_write_size);

	cache.write_offset = 0;

	cache.dict_pos_begin = cache.dict_pos_end + 1;

	if (cache.dict_pos_begin == handle->dicBufSize) {
		/** We reached the end of dictionary, start caching from the beginning.*/
		cache.dict_pos_begin = 0;
	}

	SizeT const dictReadSize =
			(handle->dicBufSize - cache.dict_pos_begin) < sizeof(cache.data) ?
				(handle->dicBufSize - cache.dict_pos_begin)
				: sizeof(cache.data);

	cache.dict_pos_end = cache.dict_pos_begin + dictReadSize - 1;

	ext_dict->read(cache.dict_pos_begin, cache.data, dictReadSize);

	cache.invalid = false;
}
#endif

/**
 * @brief Check the instance of lzma_codec during API calls.
 */
static int check_inst(void *inst)
{
#if defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
	if (inst != CONTAINER_OF(ext_dict, lzma_codec, dict_if)) {
		return -EINVAL;
	}
#else
	ARG_UNUSED(inst);
#endif
	return 0;
}

static int lzma_reset(void *inst);

static int lzma_init(void *inst)
{
	int rc = 0;

#if defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
	if (inst == NULL)
		return -EINVAL;

	ext_dict = &((lzma_codec *)inst)->dict_if;
	if (ext_dict->open == NULL || ext_dict->close == NULL
	    || ext_dict->write == NULL || ext_dict->read == NULL) {
		return -EINVAL;
	}
#else
	ARG_UNUSED(inst);
#endif

#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_MALLOC) \
	&& !defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
	if (lzma_dict != NULL) {
		/* Already allocated */
		lzma_reset(inst);

		return rc;
	}

#if CONFIG_NRF_COMPRESS_MEMORY_ALIGNMENT > 1
	lzma_dict = (uint8_t *)aligned_alloc(CONFIG_NRF_COMPRESS_MEMORY_ALIGNMENT,
					     MAX_LZMA_DICT_SIZE);
#else
	lzma_dict = (uint8_t *)malloc(MAX_LZMA_DICT_SIZE);
#endif

	if (lzma_dict == NULL) {
		rc = -ENOMEM;
	}
#endif

	return rc;
}

static int lzma_deinit(void *inst)
{
	int const arg_check_rc = check_inst(inst);

	if (arg_check_rc)
		return arg_check_rc;

#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_MALLOC) \
	&& !defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
	if (lzma_dict != NULL) {
#ifdef CONFIG_NRF_COMPRESS_CLEANUP
		memset(lzma_dict, 0x00, MAX_LZMA_DICT_SIZE);
#endif

		free(lzma_dict);
		lzma_dict = NULL;
	}
#endif

	lzma_reset(inst);
#if defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
	ext_dict = NULL;
#endif

	return 0;
}

static int lzma_reset(void *inst)
{
	int const arg_check_rc = check_inst(inst);

	if (arg_check_rc)
		return arg_check_rc;

	if (allocated_probs) {
		allocated_probs = false;

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		Lzma2Dec_FreeProbs(&lzma_decoder, &lzma_probs_allocator);

#ifdef CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY
		if (lzma_decoder.decoder.dicHandle->isOpened)
			LzmaDictionaryClose(lzma_decoder.decoder.dicHandle);
#endif
		lzma_decoder.decoder.dicPos = 0;
#else
		LzmaDec_FreeProbs(&lzma_decoder, &lzma_probs_allocator);
#ifdef CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY
		if (lzma_decoder.dicHandle->isOpened)
			LzmaDictionaryClose(lzma_decoder.decoder.dicHandle);
#endif
		lzma_decoder.dicPos = 0;
#endif
	}

	return 0;
}

static size_t lzma_bytes_needed(void *inst)
{
	int const arg_check_rc = check_inst(inst);
	if (arg_check_rc)
		return arg_check_rc;

#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_MALLOC) \
	&& !defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
	if (lzma_dict == NULL) {
		return 0;
	}
#endif

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
	return (allocated_probs ? CONFIG_NRF_COMPRESS_CHUNK_SIZE : LZMA2_HEADER_SIZE);
#else
	return (allocated_probs ? CONFIG_NRF_COMPRESS_CHUNK_SIZE : LZMA_PROPS_SIZE);
#endif
}

#if !defined(CONFIG_NRF_COMPRESS_EXTERNAL_DICTIONARY)
static int lzma_decompress(void *inst, const uint8_t *input, size_t input_size, bool last_part,
			   uint32_t *offset, uint8_t **output, size_t *output_size)
{
	int rc;
	ELzmaStatus status;
	size_t chunk_size = input_size;

	int const arg_check_rc = check_inst(inst);

	if (arg_check_rc)
		return arg_check_rc;

#if defined(CONFIG_NRF_COMPRESS_MEMORY_TYPE_MALLOC)
	if (lzma_dict == NULL) {
		return -ESRCH;
	}
#endif

	if (input == NULL || input_size == 0 || offset == NULL || output == NULL ||
	    output_size == NULL) {
		return -EINVAL;
	}

	*output = NULL;
	*output_size = 0;

	if (!allocated_probs) {
#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		rc = Lzma2Dec_AllocateProbs(&lzma_decoder, input[0], &lzma_probs_allocator);
#else
		rc = LzmaDec_AllocateProbs(&lzma_decoder, input, LZMA_PROPS_SIZE,
					   &lzma_probs_allocator);
#endif

		if (rc) {
			rc = -EINVAL;
			goto done;
		}

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		if (lzma_decoder.decoder.prop.dicSize > MAX_LZMA_DICT_SIZE) {
#else
		if (lzma_decoder.prop.dicSize > MAX_LZMA_DICT_SIZE) {
#endif
			rc = -EINVAL;
#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
			Lzma2Dec_FreeProbs(&lzma_decoder, &lzma_probs_allocator);
#else
			LzmaDec_FreeProbs(&lzma_decoder, &lzma_probs_allocator);
#endif
			goto done;
		}

		allocated_probs = true;
#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		*offset = LZMA2_HEADER_SIZE;
#else
		/* Header and account for uncompressed size */
		*offset = LZMA_PROPS_SIZE + sizeof(uint64_t);
#endif

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		lzma_decoder.decoder.dic = lzma_dict;
		lzma_decoder.decoder.dicBufSize = MAX_LZMA_DICT_SIZE;
		Lzma2Dec_Init(&lzma_decoder);
#else
		lzma_decoder.dic = lzma_dict;
		lzma_decoder.dicBufSize = MAX_LZMA_DICT_SIZE;
		LzmaDec_Init(&lzma_decoder);
#endif

		return 0;
	}

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
	rc = Lzma2Dec_DecodeToDic(&lzma_decoder, MAX_LZMA_DICT_SIZE, input, &chunk_size,
					(last_part ? LZMA_FINISH_END : LZMA_FINISH_ANY), &status);
#else
	rc = LzmaDec_DecodeToDic(&lzma_decoder, MAX_LZMA_DICT_SIZE, input, &chunk_size,
					(last_part ? LZMA_FINISH_END : LZMA_FINISH_ANY), &status);
#endif
	if (rc) {
		rc = -EINVAL;
		goto done;
	}

	*offset = chunk_size;

	if (last_part && (status == LZMA_STATUS_FINISHED_WITH_MARK ||
			  status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK) &&
	    *offset < input_size) {
		/* If last block, ensure offset matches complete file size */
		*offset = input_size;
	}

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
	if (lzma_decoder.decoder.dicPos >= lzma_decoder.decoder.dicBufSize ||
	    (last_part && input_size == chunk_size)) {
		*output = lzma_decoder.decoder.dic;
		*output_size = lzma_decoder.decoder.dicPos;
		lzma_decoder.decoder.dicPos = 0;
	}
#else
	if (lzma_decoder.dicPos >= lzma_decoder.dicBufSize ||
	    (last_part && input_size == chunk_size)) {
		*output = lzma_decoder.dic;
		*output_size = lzma_decoder.dicPos;
		lzma_decoder.dicPos = 0;
	}
#endif

done:
	return rc;
}
#else
static int lzma_decompress(void *inst, const uint8_t *input, size_t input_size, bool last_part,
			   uint32_t *offset, uint8_t **output, size_t *output_size)
{
	int rc;
	ELzmaStatus status;
	size_t chunk_size = input_size;
	CLzmaDec *decoder;

	int const arg_check_rc = check_inst(inst);

	if (arg_check_rc)
		return arg_check_rc;

	if (input == NULL || input_size == 0 || offset == NULL || output == NULL ||
	    output_size == NULL) {
		return -EINVAL;
	}

	*output = NULL;
	*output_size = 0;

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
	decoder = &lzma_decoder.decoder;
#else
	decoder = &lzma_decoder;
#endif

	if (!allocated_probs) {
#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		rc = Lzma2Dec_AllocateProbs(&lzma_decoder, input[0], &lzma_probs_allocator);
#else
		rc = LzmaDec_AllocateProbs(&lzma_decoder, input, LZMA_PROPS_SIZE,
					   &lzma_probs_allocator);
#endif

		if (rc) {
			LOG_ERR("allocateProvs failed, rc = %d", rc);
			rc = -EINVAL;
			goto done;
		}

		decoder->dicHandle = LzmaDictionaryOpen(decoder->prop.dicSize);

		if (decoder->dicHandle == NULL) {
			rc = -EINVAL;
#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
			Lzma2Dec_FreeProbs(&lzma_decoder, &lzma_probs_allocator);
#else
			LzmaDec_FreeProbs(&lzma_decoder, &lzma_probs_allocator);
#endif
			goto done;
		}

		allocated_probs = true;
#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		*offset = LZMA2_HEADER_SIZE;
#else
		/* Header and account for uncompressed size */
		*offset = LZMA_PROPS_SIZE + sizeof(uint64_t);
#endif

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
		Lzma2Dec_Init(&lzma_decoder);
#else
		LzmaDec_Init(&lzma_decoder);
#endif

		return 0;
	}

#ifdef CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
	rc = Lzma2Dec_DecodeToDic(&lzma_decoder, decoder->dicHandle->dicBufSize, input, &chunk_size,
					LZMA_FINISH_ANY, &status);
#else
	rc = LzmaDec_DecodeToDic(&lzma_decoder, decoder->dicHandle->dicBufSize, input, &chunk_size,
					LZMA_FINISH_ANY, &status);
#endif
	if (rc) {
		LOG_ERR("decodeToDic failed, rc = %d", rc);
		rc = -EINVAL;
		goto done;
	}

	*offset = chunk_size;

	if (last_part && (status == LZMA_STATUS_FINISHED_WITH_MARK) &&
	    *offset < input_size) {
		/* If last block, ensure offset matches complete file size */
		*offset = input_size;
	}

	if (decoder->dicPos >= decoder->dicHandle->dicBufSize ||
	    (last_part && input_size == *offset)) {
#if CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE > 0
		if (cache.invalid) {
			validate_cache(decoder->dicHandle);
		}
#endif
		*output_size = decoder->dicPos;
		decoder->dicPos = 0;
	}

done:
	return rc;
}

static DictHandle dict_handle;

DictHandle *LzmaDictionaryOpen(SizeT size)
{
	if (dict_handle.isOpened)
		return &dict_handle;

	if (ext_dict ==  NULL)
		return NULL;

	size_t dict_size;

	if (ext_dict->open((size_t)size, &dict_size) != 0) {
		LOG_WRN("Unable to open external dictionary with size %u", size);
		return NULL;
	}

	dict_handle.isOpened = True;
	dict_handle.dicBufSize = dict_size;

#if CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE > 0
	cache.dict_pos_begin = 0;
	cache.dict_pos_end = sizeof(cache.data) - 1;
	cache.write_offset = 0;
#endif

	return &dict_handle;
}

SizeT LzmaDictionaryWrite(DictHandle *handle, SizeT pos, const Byte *data, SizeT len)
{
	if (handle != &dict_handle || ext_dict == NULL)
		return 0;

	SizeT write_len = len;

	if (pos + len > handle->dicBufSize) {
		write_len = handle->dicBufSize - pos;
	}

#if CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE > 0
	if (pos > cache.dict_pos_end || pos < cache.dict_pos_begin) {
		/*
		 * Should never happen, lzma operates on dicPos when writing to dictionary,
		 * which should be aligned with cache.
		 */
		return 0;
	}

	SizeT bytes_written = 0;
	// SizeT cache_pos = pos - cache.dict_pos_begin;

	while (bytes_written != write_len) {
		SizeT cache_write_len =
			(write_len - bytes_written) > (sizeof(cache.data) - cache.write_offset) ?
				(sizeof(cache.data) - cache.write_offset) :
				(write_len - bytes_written);

		memcpy(cache.data + cache.write_offset, data + bytes_written, cache_write_len);
		cache.invalid = true;

		bytes_written += cache_write_len;
		cache.write_offset += cache_write_len;

		if (cache.write_offset == sizeof(cache.data)) {
			/** Cache full, validate it.*/
			validate_cache(handle);
		}
	}
#else
	ext_dict->write(pos, data, write_len);
#endif
	return write_len;
}

SizeT LzmaDictionaryRead(DictHandle *handle, SizeT pos, Byte *data, SizeT len)
{
	if (handle != &dict_handle || ext_dict == NULL)
		return 0;

	int read_len = len;

	if (pos + len > handle->dicBufSize) {
		read_len = handle->dicBufSize - pos;
	}

#if CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE > 0
	SizeT bytes_read = 0;

	if (pos + read_len > cache.dict_pos_begin && pos <= cache.dict_pos_end) {
		/** We have at least some of the requested data in the cache. */
		SizeT cache_pos;
		SizeT cache_copy_size;

		if (pos < cache.dict_pos_begin) {
			/** First part of data is from dictionary... */
			ext_dict->read(pos, data, cache.dict_pos_begin - pos);
			bytes_read = cache.dict_pos_begin - pos;

			cache_pos = 0;
		} else {
			cache_pos = pos - cache.dict_pos_begin;
		}

		cache_copy_size = (pos + read_len > cache.dict_pos_end) ?
				(sizeof(cache.data) - cache_pos)
				: (read_len - bytes_read);
		memcpy(data + bytes_read, cache.data + cache_pos, cache_copy_size);

		bytes_read += cache_copy_size;

		if (bytes_read != read_len) {
			/** Last part of data is from dictionary.*/
			ext_dict->read(pos + bytes_read, data + bytes_read,
					read_len - bytes_read);
		}
	} else {
		/** Requested data is not cached at all.*/
		ext_dict->read(pos, data, read_len);
	}

#else
	ext_dict->read(pos, data, read_len);
#endif
	return read_len;
}

SRes LzmaDictionaryClose(DictHandle *handle)
{
	if (handle != &dict_handle || ext_dict == NULL)
		return SZ_ERROR_PARAM;

#if CONFIG_NRF_COMPRESS_DICTIONARY_CACHE_SIZE > 0
	if (handle->isOpened && cache.invalid)
		validate_cache(handle);

	/** Clear the cache.*/
	memset(cache.data, 0, sizeof(cache.data));
#endif

	if (ext_dict->close() != 0)
		return SZ_ERROR_FAIL;

	dict_handle.isOpened = False;

	return SZ_OK;
}
#endif

NRF_COMPRESS_IMPLEMENTATION_DEFINE(lzma, NRF_COMPRESS_TYPE_LZMA, lzma_init, lzma_deinit,
				   lzma_reset, NULL, lzma_bytes_needed, lzma_decompress);
