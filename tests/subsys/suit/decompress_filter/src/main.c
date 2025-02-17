/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/ztest.h>
#include <zephyr/fff.h>
#include <suit_decompress_filter.h>
#include <suit_ram_sink.h>
#include <suit_flash_sink.h>
#include <suit_memptr_streamer.h>
#include <suit_plat_mem_util.h>
#include <mbedtls/sha256.h>

#define FLASH_AREA_SIZE	  (128 * 0x400)
#define WRITE_ADDR		  suit_plat_mem_nvm_ptr_get(SUIT_DFU_PARTITION_OFFSET)

#define SUIT_DFU_PARTITION_OFFSET FIXED_PARTITION_OFFSET(dfu_partition)
#define SUIT_DFU_PARTITION_SIZE	  FIXED_PARTITION_SIZE(dfu_partition)

const suit_manifest_class_id_t decompress_test_sample_class_id = {
	{0x5b, 0x46, 0x9f, 0xd1, 0x90, 0xee, 0x53, 0x9c, 0xa3, 0x18, 0x68, 0x1b, 0x03, 0x69, 0x5e,
	 0x36}};

static uint8_t output_buffer[128*1024] = {0};

/* Input valid lzma2 compressed data */
const uint8_t dummy_data_input[] = {
#include "dummy_data_input.inc"
};

/* File size and sha256 hash of decompressed data */
const uint32_t dummy_data_output_size = 66477;

#define SHA256_SIZE 32

const uint8_t dummy_data_output_sha256[] = {
	0x87, 0xee, 0x2e, 0x17, 0xa5, 0xdb, 0x98, 0xbe,
	0x8c, 0xcb, 0xfe, 0xc9, 0x70, 0x8c, 0x7a, 0x43,
	0x66, 0xda, 0x63, 0xff, 0x48, 0x15, 0x48, 0x88,
	0xd7, 0xed, 0x64, 0x87, 0xba, 0xb9, 0xef, 0xc5
};


struct suit_decompress_filter_tests_fixture {
	/* Empty for now. */
};

static void *test_suite_setup(void)
{
	static struct suit_decompress_filter_tests_fixture fixture;

	return &fixture;
}

static void test_suite_teardown(void *f)
{
	ARG_UNUSED(f);
}

static void test_before(void *f)
{
	ARG_UNUSED(f);
}

ZTEST_SUITE(suit_decompress_filter_tests, NULL, test_suite_setup, test_before, NULL,
	    test_suite_teardown);

ZTEST_F(suit_decompress_filter_tests, test_RAM_sink_sucessful_decompress)
{
	struct stream_sink compress_sink;
	struct stream_sink ram_sink;
	struct suit_compression_info compression_info = {
		.compression_alg_id = suit_lzma2,
		.arm_thumb_filter = false,
	};
	uint8_t output_sha[SHA256_SIZE] = { 0 };
	size_t output_size;
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);
    int rc = mbedtls_sha256_starts(&ctx, false);

	zassert_ok(rc, "Expected mbedtls sha256 start to be successful");

	suit_plat_err_t err = suit_ram_sink_get(&ram_sink, output_buffer, sizeof(output_buffer));

	zassert_equal(err, SUIT_PLAT_SUCCESS, "Unable to create RAM sink");

	err = suit_decompress_filter_get(&compress_sink, &compression_info,
				&decompress_test_sample_class_id, &ram_sink);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to create decompress filter, err = %d", err);

	err = suit_memptr_streamer_stream(dummy_data_input,
						sizeof(dummy_data_input), &compress_sink);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to decompress binary blob");

	err = compress_sink.flush(compress_sink.ctx);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to flush decompress filter");

	err = compress_sink.used_storage(compress_sink.ctx, &output_size);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to get binary image size");

	printf("size = %d\n", output_size);

	rc = mbedtls_sha256_update(&ctx, output_buffer, output_size);
	zassert_ok(rc, "Expected hash update to be successful");

	rc = mbedtls_sha256_finish(&ctx, output_sha);
	mbedtls_sha256_free(&ctx);
	zassert_ok(rc, "Expected mbedtls sha256 finish to be successful");

	zassert_mem_equal(output_sha, dummy_data_output_sha256, SHA256_SIZE,
			  "Expected hash to match");

	err = compress_sink.release(compress_sink.ctx);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to release decompress filter");

}

ZTEST_F(suit_decompress_filter_tests, test_flash_sink_sucessful_decompress)
{
	struct stream_sink compress_sink;
	struct stream_sink flash_sink;
	struct suit_compression_info compression_info = {
		.compression_alg_id = suit_lzma2,
		.arm_thumb_filter = false,
	};
	uint8_t output_sha[SHA256_SIZE] = { 0 };
	size_t output_size;
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);
    int rc = mbedtls_sha256_starts(&ctx, false);

	zassert_ok(rc, "Expected mbedtls sha256 start to be successful");

	suit_plat_err_t err = suit_flash_sink_get(&flash_sink, WRITE_ADDR, FLASH_AREA_SIZE);

	zassert_equal(err, SUIT_PLAT_SUCCESS, "Unable to create flash sink");

	err = suit_decompress_filter_get(&compress_sink, &compression_info,
				&decompress_test_sample_class_id, &flash_sink);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to create decompress filter, err = %d", err);

	err = suit_memptr_streamer_stream(dummy_data_input,
						sizeof(dummy_data_input), &compress_sink);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to decompress binary blob");

	err = compress_sink.flush(compress_sink.ctx);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to flush decompress filter");

	err = compress_sink.used_storage(compress_sink.ctx, &output_size);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to get binary image size");

	err = flash_sink.readback(flash_sink.ctx, 0, output_buffer, output_size);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to get binary image data");

	rc = mbedtls_sha256_update(&ctx, output_buffer, output_size);
	zassert_ok(rc, "Expected hash update to be successful");

	rc = mbedtls_sha256_finish(&ctx, output_sha);
	mbedtls_sha256_free(&ctx);
	zassert_ok(rc, "Expected mbedtls sha256 finish to be successful");

	zassert_mem_equal(output_sha, dummy_data_output_sha256, SHA256_SIZE,
			  "Expected hash to match");

	err = compress_sink.release(compress_sink.ctx);
	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to release decompress filter");

}
