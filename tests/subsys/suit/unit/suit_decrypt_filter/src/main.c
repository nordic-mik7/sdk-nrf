/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <suit_decrypt_filter.h>
#include <suit_mci.h>
#include <zephyr/fff.h>
#include <zephyr/ztest.h>
#include <psa/crypto.h>
#include <mocks.h>

#define KEY_ID_FWENC_APPLICATION_GEN1 0x40022000

#define ENC_INFO_DEFAULT_INIT { \
							    .enc_alg_id = suit_cose_aes256_gcm, \
							    .IV = { \
							  		     .value = iv_direct, \
				                         .len = sizeof(iv_direct), \
			                          }, \
		                        .aad = { \
				                          .value = aad, \
				                          .len = sizeof(aad), \
			                           }, \
		                        .kw_alg_id = suit_cose_direct, \
		                        .kw_key.direct = {.key_id = {.value = cek_key_id_cbor, \
			                    .len = sizeof(cek_key_id_cbor)},} \
	                           }

/**
 * Encryption without wrapping CEK achieved by running:
 *
 * echo "This is a sample plaintext for testing the decryption filter" > plaintext.txt
 * nrfkms encrypt -k  TEST_AES_KEY -c test -f plaintext.txt --aad "sample aad" --format native
 *
 * Ciphertext and NONCE (IV) taken from the encrypted_data_using_TEST_AES_KEY-test.bin file,
 * which is in format |nonce (12 bytes)|tag (16 bytes)|ciphertext|
 */

static const uint8_t ciphertext_direct[] = {
	/* tag (16 bytes) */
	0x4d, 0x21, 0x30, 0xb7, 0xce, 0x8a, 0xd6, 0x00, 0xe4, 0x04, 0xbb, 0x32,
	0x72, 0x7a, 0xbb, 0x7c,
	/* ciphertext */
	0xf0, 0x72, 0xdb, 0x63, 0x03, 0xdd, 0x24, 0x69,
	0xd4, 0xbf, 0xd7, 0xa0, 0xec, 0xfa, 0x66, 0x58, 0x95, 0x2b, 0xc1, 0xc2,
	0x9d, 0x82, 0x02, 0x1a, 0xd7, 0x5b, 0xc0, 0x01, 0xce, 0x0b, 0x79, 0x53,
	0xe7, 0xdb, 0x0d, 0x35, 0xab, 0xef, 0x81, 0xc8, 0x68, 0xc5, 0xa7, 0x22,
	0x90, 0xea, 0xd0, 0x7f, 0x36, 0xed, 0x14, 0xbe, 0x30, 0xf2, 0x81, 0x56,
	0x7e, 0x2e, 0x5f, 0xd8, 0x7c,
};


static const uint8_t iv_direct[] = {
	0x60, 0x90, 0x6d, 0xb2, 0xfe, 0xc3, 0xc8, 0x5a, 0xf0, 0x28, 0xb1, 0xb6,
};

static const suit_manifest_class_id_t sample_class_id = {
	{0x5b, 0x46, 0x9f, 0xd1, 0x90, 0xee, 0x53, 0x9c, 0xa3, 0x18, 0x68, 0x1b, 0x03, 0x69, 0x5e,
	 0x36}
};

static const uint8_t cek_key_id_cbor[] = {
		0x1A, 0x40, 0x02, 0x20, 0x00,
	};

struct suit_decrypt_filter_tests_fixture {
	struct stream_sink dec_sink;
    struct stream_sink ram_sink;	
	size_t decrypted_output_length;
	psa_status_t aead_update_status;
	psa_status_t aead_verify_status;
	suit_plat_err_t ram_sink_write_status;

	// ram_sink interfaces call counters. Not really 'fixtures', but something 
	// we verify as a side effect of test run. 
	int ram_sink_write_call_cnt;
	int ram_sink_erase_call_cnt;
	int ram_sink_release_call_cnt;
};

static struct suit_decrypt_filter_tests_fixture tests_fixture;

static const uint8_t aad[] = {
	"sample aad"
};

// Custom fake functions implementation - for returning values by reference
static suit_plat_err_t custom_suit_plat_decode_key_id(struct zcbor_string *key_id, uint32_t *integer_key_id)
{
	(void)key_id;

	*integer_key_id = KEY_ID_FWENC_APPLICATION_GEN1;
	return SUIT_PLAT_SUCCESS;
}

static psa_status_t custom_psa_aead_update(psa_aead_operation_t *operation,
                             			   const uint8_t *input,
                             			   size_t input_length,
                             			   uint8_t *output,
                             			   size_t output_size,
                             			   size_t *output_length)
{
	(void)operation;
	(void)input;
	(void)input_length;
	(void)output;
	(void)output_size;

	*output_length = tests_fixture.decrypted_output_length;

	return tests_fixture.aead_update_status;
}

static psa_status_t custom_psa_aead_verify(psa_aead_operation_t *operation,
                             			   uint8_t *plaintext,
                             			   size_t plaintext_size,
                             			   size_t *plaintext_length,
                             			   const uint8_t *tag,
                             			   size_t tag_length)
{
	(void)operation;
	(void)plaintext;
	(void)plaintext_size;
	(void)tag;
	(void)tag_length;

	*plaintext_length = tests_fixture.decrypted_output_length;

	return tests_fixture.aead_verify_status;
}

// dummy interface functions for the decrypted data output sink (fixture->ram_sink)
static suit_plat_err_t release(void *ctx)
{
	(void)ctx;

	tests_fixture.ram_sink_release_call_cnt++;

	return SUIT_PLAT_SUCCESS;
}

static suit_plat_err_t erase(void *ctx)
{
	(void)ctx;

	tests_fixture.ram_sink_erase_call_cnt++;

	return SUIT_PLAT_SUCCESS;
}

static suit_plat_err_t write_ram(void *ctx, const uint8_t *buf, size_t size)
{

	(void)ctx;
	(void)buf;
	(void)size;

	tests_fixture.ram_sink_write_call_cnt++;

	return tests_fixture.ram_sink_write_status;
}

static suit_plat_err_t used_storage(void *ctx, size_t *size)
{
	(void)ctx;
	(void)size;

	return SUIT_PLAT_SUCCESS;
}

static void *test_suite_setup(void)
{
	return &tests_fixture;
}

static void test_suite_teardown(void *fixture)
{
	(void)fixture;
}

static void test_before(void *f)
{
	struct suit_decrypt_filter_tests_fixture *fixture = 
			(struct suit_decrypt_filter_tests_fixture* )f;

	/* Reset mocks */
	mocks_reset();

	/* Reset common FFF internal structures */
	FFF_RESET_HISTORY();

	if (fixture->dec_sink.release && fixture->dec_sink.ctx)
	{
		fixture->dec_sink.release(fixture->dec_sink.ctx);
	}
	
	memset(fixture, 0, sizeof(struct suit_decrypt_filter_tests_fixture));
	fixture->ram_sink.write = write_ram;
	fixture->ram_sink.used_storage = used_storage;
	fixture->ram_sink.erase = erase;
	fixture->ram_sink.release = release;
}

ZTEST_SUITE(suit_decrypt_filter_tests, NULL, test_suite_setup, test_before, 
		NULL, test_suite_teardown);

ZTEST_F(suit_decrypt_filter_tests, test_key_id_validation_fail)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_mci_fw_encryption_key_id_validate_fake.return_val = MCI_ERR_WRONGKEYID;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;

	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);
	
	zassert_equal(err, SUIT_PLAT_ERR_AUTHENTICATION,
		    "Incorrect error code when getting decrypt filter");
	zassert_equal(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		    "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			"Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 0,
			"Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 0,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 0,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 0,
			"Invalid number of calls to psa_aead_abort");
	zassert_equal_ptr(fixture->dec_sink.ctx, NULL,
			"Invalid fixture->dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_decryption_setup_fail)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_ERROR_GENERIC_ERROR;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);
	
	zassert_equal(err, SUIT_PLAT_ERR_CRASH,
		    "Incorrect error code when getting decrypt filter");
	zassert_equal(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		    "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			"Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 1,
			"Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 0,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 0,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 1,
			"Invalid number of calls to psa_aead_abort");
	zassert_equal_ptr(fixture->dec_sink.ctx, NULL,
			"Invalid fixture->dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_decryption_set_nonce_fail)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_SUCCESS;
	psa_aead_set_nonce_fake.return_val = PSA_ERROR_GENERIC_ERROR;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);
	
	zassert_equal(err, SUIT_PLAT_ERR_CRASH,
		    "Incorrect error code when getting decrypt filter");
	zassert_equal(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		    "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			"Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 1,
			"Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg1_val, iv_direct,
			"Invalid IV passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.arg2_val, sizeof(iv_direct),
			"Invalid IV length passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 1,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 0,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 1,
			"Invalid number of calls to psa_aead_abort");
	zassert_equal_ptr(fixture->dec_sink.ctx, NULL,
			"Invalid fixture->dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_decryption_update_ad_fail)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_SUCCESS;
	psa_aead_set_nonce_fake.return_val = PSA_SUCCESS;
	psa_aead_update_ad_fake.return_val = PSA_ERROR_GENERIC_ERROR;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);
	
	zassert_equal(err, SUIT_PLAT_ERR_CRASH,
		    "Incorrect error code when getting decrypt filter");
	zassert_equal(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		    "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			"Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 1,
			 "Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg1_val, iv_direct,
			 "Invalid IV passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.arg2_val, sizeof(iv_direct),
			 "Invalid IV length passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 1,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 1,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal_ptr(psa_aead_update_ad_fake.arg1_val, aad,
			 "Invalid ad passed to psa_aead_update_ad");
	zassert_equal(psa_aead_update_ad_fake.arg2_val, sizeof(aad),
			 "Invalid ad length passed to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 1,
			"Invalid number of calls to psa_aead_abort");
	zassert_equal_ptr(fixture->dec_sink.ctx, NULL,
			"Invalid fixture->dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_filter_get_happy_path)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_SUCCESS;
	psa_aead_set_nonce_fake.return_val = PSA_SUCCESS;
	psa_aead_update_ad_fake.return_val = PSA_SUCCESS;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);
	
	zassert_equal(err, SUIT_PLAT_SUCCESS,
		    "Incorrect error code when getting decrypt filter");
	zassert_equal(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		    "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			"Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 1,
			 "Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg1_val, iv_direct,
			 "Invalid IV passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.arg2_val, sizeof(iv_direct),
			 "Invalid IV length passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 1,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 1,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal_ptr(psa_aead_update_ad_fake.arg1_val, aad,
			 "Invalid ad passed to psa_aead_update_ad");
	zassert_equal(psa_aead_update_ad_fake.arg2_val, sizeof(aad),
			 "Invalid ad length passed to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 0,
			"Invalid number of calls to psa_aead_abort");
	zassert_not_equal(   fixture->dec_sink.ctx && fixture->dec_sink.write 
					  && fixture->dec_sink.erase && fixture->dec_sink.release 
					  && fixture->dec_sink.flush && fixture->dec_sink.used_storage, 0,
			"Invalid fixture->dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_write_filter_not_initialized)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_plat_decode_key_id_fake.custom_fake = custom_suit_plat_decode_key_id;

	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);

	zassert_equal(err, SUIT_PLAT_SUCCESS,
		    "Incorrect error code when getting decrypt filter");
	
	err = fixture->dec_sink.release(fixture->dec_sink.ctx);

	// we expect SUIT_PLAT_ERR_INCORRECT_STATE because we didn't store any tag data.
	zassert_equal(err, SUIT_PLAT_ERR_INCORRECT_STATE,
			"Incorrect error code when releasing filter");
	zassert_equal(fixture->ram_sink_release_call_cnt, 1,
			"Incorrect number of ram_sink release function calls");
	
	err = fixture->dec_sink.write(fixture->dec_sink.ctx, ciphertext_direct, 
								sizeof(ciphertext_direct));

	zassert_equal(err, SUIT_PLAT_ERR_INVAL,
			"Incorrect error code when calling filter write interface");
}

ZTEST_F(suit_decrypt_filter_tests, test_write_happy_path)
{
	const uint8_t dummy_decrypted_array[256]; // Array of random values big enoguh to 
											  // exceed SINGLE_CHUNK_SIZE in decrypt filter.
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_plat_decode_key_id_fake.custom_fake = custom_suit_plat_decode_key_id;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);

	zassert_equal(err, SUIT_PLAT_SUCCESS,
		    "Incorrect error code when getting decrypt filter");

	psa_aead_update_fake.custom_fake = custom_psa_aead_update;
	fixture->aead_update_status = PSA_SUCCESS;
	fixture->decrypted_output_length = 100; // Anything greater than 0.
	
	err = fixture->dec_sink.write(fixture->dec_sink.ctx, dummy_decrypted_array, 
								sizeof(dummy_decrypted_array));

	zassert_equal(err, SUIT_PLAT_SUCCESS,
			"Incorrect error code when calling filter write interface");
	zassert_equal(fixture->ram_sink_write_call_cnt, 2,
			"Incorrect number of ram_sink write function calls");
}

ZTEST_F(suit_decrypt_filter_tests, test_flush_verify_fail)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_plat_decode_key_id_fake.custom_fake = custom_suit_plat_decode_key_id;
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);

	zassert_equal(err, SUIT_PLAT_SUCCESS,
		    "Incorrect error code when getting decrypt filter");

	psa_aead_update_fake.custom_fake = custom_psa_aead_update;
	fixture->aead_update_status = PSA_SUCCESS;
	fixture->decrypted_output_length = 100; // Anything greater than 0.

	err = fixture->dec_sink.write(fixture->dec_sink.ctx, ciphertext_direct, 
								sizeof(ciphertext_direct));
	
	zassert_equal(err, SUIT_PLAT_SUCCESS,
			"Incorrect error code when calling filter write interface");

	psa_aead_verify_fake.custom_fake = custom_psa_aead_verify;
	fixture->aead_verify_status = PSA_ERROR_GENERIC_ERROR;
	
	err = fixture->dec_sink.flush(fixture->dec_sink.ctx);

	zassert_equal(err, SUIT_PLAT_ERR_AUTHENTICATION,
			"Incorrect error code when calling filter flush interface");
	zassert_equal(fixture->ram_sink_erase_call_cnt, 1,
			"Incorrect number of ram_sink write function calls");
	zassert_equal(psa_aead_abort_fake.call_count, 1,
			"Invalid number of calls to psa_aead_abort");
}

ZTEST_F(suit_decrypt_filter_tests, test_flush_happy_path)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_plat_decode_key_id_fake.custom_fake = custom_suit_plat_decode_key_id;
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);

	zassert_equal(err, SUIT_PLAT_SUCCESS,
		    "Incorrect error code when getting decrypt filter");

	psa_aead_update_fake.custom_fake = custom_psa_aead_update;
	fixture->aead_update_status = PSA_SUCCESS;
	fixture->decrypted_output_length = 100; // Anything greater than 0.

	err = fixture->dec_sink.write(fixture->dec_sink.ctx, ciphertext_direct, 
								sizeof(ciphertext_direct));
	
	zassert_equal(err, SUIT_PLAT_SUCCESS,
			"Incorrect error code when calling filter write interface");

	psa_aead_verify_fake.custom_fake = custom_psa_aead_verify;
	fixture->aead_verify_status = PSA_SUCCESS;
	fixture->decrypted_output_length = 100; // Anything greater than 0.
	
	err = fixture->dec_sink.flush(fixture->dec_sink.ctx);

	zassert_equal(err, SUIT_PLAT_SUCCESS,
			"Incorrect error code when calling filter flush interface");
	zassert_equal(fixture->ram_sink_write_call_cnt, 2, // Called 2 times because we
													   // also call write (< SINGLE_CHUNK_SIZE).
			"Incorrect number of ram_sink write function calls");
	zassert_equal(psa_aead_abort_fake.call_count, 0,
			"Invalid number of calls to psa_aead_abort");
}

ZTEST_F(suit_decrypt_filter_tests, test_flush_ram_write_fail)
{
	struct suit_encryption_info enc_info = ENC_INFO_DEFAULT_INIT;

	suit_plat_decode_key_id_fake.custom_fake = custom_suit_plat_decode_key_id;
	suit_plat_err_t err = suit_decrypt_filter_get(&fixture->dec_sink, &enc_info, 
											&sample_class_id, &fixture->ram_sink);

	zassert_equal(err, SUIT_PLAT_SUCCESS,
		    "Incorrect error code when getting decrypt filter");

	psa_aead_update_fake.custom_fake = custom_psa_aead_update;
	fixture->aead_update_status = PSA_SUCCESS;
	fixture->decrypted_output_length = 100; // Anything greater than 0.

	err = fixture->dec_sink.write(fixture->dec_sink.ctx, ciphertext_direct, 
								sizeof(ciphertext_direct));
	
	zassert_equal(err, SUIT_PLAT_SUCCESS,
			"Incorrect error code when calling filter write interface");

	psa_aead_verify_fake.custom_fake = custom_psa_aead_verify;
	fixture->aead_verify_status = PSA_SUCCESS;
	fixture->decrypted_output_length = 100; // Anything greater than 0.
	tests_fixture.ram_sink_write_status = SUIT_PLAT_ERR_NOMEM;

	err = fixture->dec_sink.flush(fixture->dec_sink.ctx);

	zassert_equal(err, SUIT_PLAT_ERR_NOMEM,
			"Incorrect error code when calling filter flush interface");
	zassert_equal(fixture->ram_sink_write_call_cnt, 2, // Called 2 times because we
													   // also call write (< SINGLE_CHUNK_SIZE).
			"Incorrect number of ram_sink write function calls");
	zassert_equal(psa_aead_abort_fake.call_count, 0,
			"Invalid number of calls to psa_aead_abort");
	zassert_equal(fixture->ram_sink_erase_call_cnt, 1,
			"Incorrect number of ram_sink erase function calls");
}
