/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/ztest.h>
#include <zephyr/fff.h>
#include <suit_decompress_filter.h>
#include <suit_ram_sink.h>
#include <suit_memptr_streamer.h>

const suit_manifest_class_id_t decompress_test_sample_class_id = {
	{0x5b, 0x46, 0x9f, 0xd1, 0x90, 0xee, 0x53, 0x9c, 0xa3, 0x18, 0x68, 0x1b, 0x03, 0x69, 0x5e,
	 0x36}};

static uint8_t output_buffer[128] = {0};

/* Input valid lzma2 compressed data */
const uint8_t dummy_data_input[] = {
//#include "dummy_data_input.inc"
	0x22, 0x33, 0x44, 0x55,
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

ZTEST_F(suit_decompress_filter_tests, test_get_filter)
{
	struct stream_sink compress_sink;
	struct stream_sink ram_sink;
	struct suit_compression_info compression_info = {
		.compression_alg_id = suit_lzma2,
		.arm_thumb_filter = false,
	};

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

	err = compress_sink.release(compress_sink.ctx);

	zassert_equal(err, SUIT_PLAT_SUCCESS, "Failed to release decompress filter");

}
