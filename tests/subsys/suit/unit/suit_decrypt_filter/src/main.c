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


struct suit_decrypt_filter_tests_fixture {
	char dummy; //nothing for now
};

static const uint8_t plaintext[] = {
	"This is a sample plaintext for testing the decryption filter",
};

static const char aad[] = {
	"sample aad"
};

static struct stream_sink dec_sink = {0};

static void get_cbor_key_id(psa_key_id_t const key_id, uint8_t * const cbor_key_id, size_t const cbor_key_id_len)
{
	if (cbor_key_id_len < 5)
		return;

	/* Encode key ID as CBOR unsigned int */
	cbor_key_id[1] = ((key_id >> 24) & 0xFF);
	cbor_key_id[2] = ((key_id >> 16) & 0xFF);
	cbor_key_id[3] = ((key_id >> 8) & 0xFF);
	cbor_key_id[4] = ((key_id >> 0) & 0xFF);
}

static suit_plat_err_t write_ram(void *ctx, const uint8_t *buf, size_t size)
{
	(void)ctx;
	(void)buf;
	(void)size;

	// dummy write interface function for the decrypted data output sink 
}

static suit_plat_err_t used_storage(void *ctx, size_t *size)
{
	(void)ctx;
	(void)size;

	// dummy used_storage interface function for the decrypted data output sink
}

static void *test_suite_setup(void)
{
	static struct suit_decrypt_filter_tests_fixture fixture = {0};

	return &fixture;
}

static void test_suite_teardown(void *f)
{
	(void)f;
}

static void test_before(void *data)
{
	/* Reset mocks */
	mocks_reset();

	/* Reset common FFF internal structures */
	FFF_RESET_HISTORY();

	if (dec_sink.release && dec_sink.ctx)
	{
		printf("realese me!\n");
		dec_sink.release(dec_sink.ctx);
		memset(&dec_sink, 0, sizeof(dec_sink));
	}
}

ZTEST_SUITE(suit_decrypt_filter_tests, NULL, test_suite_setup, test_before, NULL, test_suite_teardown);

ZTEST_F(suit_decrypt_filter_tests, test_key_id_validation_fail)
{
	struct stream_sink ram_sink = {0};
	uint8_t cek_key_id_cbor[] = {
		0x1A, 0x00, 0x00, 0x00, 0x00,
	};

	get_cbor_key_id(KEY_ID_FWENC_APPLICATION_GEN1, cek_key_id_cbor, sizeof(cek_key_id_cbor));

	struct suit_encryption_info enc_info = {
		.enc_alg_id = suit_cose_aes256_gcm,
		.IV = {
				.value = iv_direct,
				.len = sizeof(iv_direct),
			},
		.aad = {
				.value = aad,
				.len = strlen(aad),
			},
		.kw_alg_id = suit_cose_direct,
		.kw_key.direct = {.key_id = {.value = cek_key_id_cbor,
			       .len = sizeof(cek_key_id_cbor)},}
	};

	ram_sink.write = write_ram;
	suit_mci_fw_encryption_key_id_validate_fake.return_val = MCI_ERR_WRONGKEYID;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;

	suit_plat_err_t err = suit_decrypt_filter_get(&dec_sink, &enc_info, &sample_class_id, &ram_sink);
	zassert_equal(err, SUIT_PLAT_ERR_AUTHENTICATION,
		      "Incorrect error code when getting decrypt filter");

	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
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
	zassert_equal(dec_sink.ctx, NULL,
			"Invalid dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_decryption_setup_fail)
{
	struct stream_sink ram_sink = {0};
	uint8_t cek_key_id_cbor[] = {
		0x1A, 0x00, 0x00, 0x00, 0x00,
	};

	get_cbor_key_id(KEY_ID_FWENC_APPLICATION_GEN1, cek_key_id_cbor, sizeof(cek_key_id_cbor));

	struct suit_encryption_info enc_info = {
		.enc_alg_id = suit_cose_aes256_gcm,
		.IV = {
				.value = iv_direct,
				.len = sizeof(iv_direct),
			},
		.aad = {
				.value = aad,
				.len = strlen(aad),
			},
		.kw_alg_id = suit_cose_direct,
		.kw_key.direct = {.key_id = {.value = cek_key_id_cbor,
			       .len = sizeof(cek_key_id_cbor)},}
	};

	ram_sink.write = write_ram;
	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_ERROR_GENERIC_ERROR;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&dec_sink, &enc_info, &sample_class_id, &ram_sink);
	zassert_equal(err, SUIT_PLAT_ERR_CRASH,
		      "Incorrect error code when getting decrypt filter");

	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
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
	zassert_equal(dec_sink.ctx, NULL,
			"Invalid dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_decryption_set_nonce_fail)
{
	struct stream_sink ram_sink = {0};
	uint8_t cek_key_id_cbor[] = {
		0x1A, 0x00, 0x00, 0x00, 0x00,
	};

	get_cbor_key_id(KEY_ID_FWENC_APPLICATION_GEN1, cek_key_id_cbor, sizeof(cek_key_id_cbor));

	struct suit_encryption_info enc_info = {
		.enc_alg_id = suit_cose_aes256_gcm,
		.IV = {
				.value = iv_direct,
				.len = sizeof(iv_direct),
			},
		.aad = {
				.value = aad,
				.len = strlen(aad),
			},
		.kw_alg_id = suit_cose_direct,
		.kw_key.direct = {.key_id = {.value = cek_key_id_cbor,
			       .len = sizeof(cek_key_id_cbor)},}
	};

	ram_sink.write = write_ram;
	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_SUCCESS;
	psa_aead_set_nonce_fake.return_val = PSA_ERROR_GENERIC_ERROR;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&dec_sink, &enc_info, &sample_class_id, &ram_sink);
	zassert_equal(err, SUIT_PLAT_ERR_CRASH,
		      "Incorrect error code when getting decrypt filter");

	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		      "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			   "Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 1,
			 "Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg1_val, iv_direct,
			 "Invalid IV passed to psa_aead_set_nonce");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg2_val, sizeof(iv_direct),
			 "Invalid IV length passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 1,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 0,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 1,
			"Invalid number of calls to psa_aead_abort");
	zassert_equal(dec_sink.ctx, NULL,
			"Invalid dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_decryption_update_ad_fail)
{
	struct stream_sink ram_sink = {0};
	uint8_t cek_key_id_cbor[] = {
		0x1A, 0x00, 0x00, 0x00, 0x00,
	};

	get_cbor_key_id(KEY_ID_FWENC_APPLICATION_GEN1, cek_key_id_cbor, sizeof(cek_key_id_cbor));

	struct suit_encryption_info enc_info = {
		.enc_alg_id = suit_cose_aes256_gcm,
		.IV = {
				.value = iv_direct,
				.len = sizeof(iv_direct),
			},
		.aad = {
				.value = aad,
				.len = strlen(aad),
			},
		.kw_alg_id = suit_cose_direct,
		.kw_key.direct = {.key_id = {.value = cek_key_id_cbor,
			       .len = sizeof(cek_key_id_cbor)},}
	};

	ram_sink.write = write_ram;
	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_SUCCESS;
	psa_aead_set_nonce_fake.return_val = PSA_SUCCESS;
	psa_aead_update_ad_fake.return_val = PSA_ERROR_GENERIC_ERROR;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&dec_sink, &enc_info, &sample_class_id, &ram_sink);
	zassert_equal(err, SUIT_PLAT_ERR_CRASH,
		      "Incorrect error code when getting decrypt filter");

	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		      "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			   "Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 1,
			 "Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg1_val, iv_direct,
			 "Invalid IV passed to psa_aead_set_nonce");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg2_val, sizeof(iv_direct),
			 "Invalid IV length passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 1,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 1,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal_ptr(psa_aead_update_ad_fake.arg1_val, aad,
			 "Invalid ad passed to psa_aead_update_ad");
	zassert_equal_ptr(psa_aead_update_ad_fake.arg2_val, strlen(aad),
			 "Invalid ad length passed to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 1,
			"Invalid number of calls to psa_aead_abort");
	zassert_equal(dec_sink.ctx, NULL,
			"Invalid dec_sink.ctx value");
}

ZTEST_F(suit_decrypt_filter_tests, test_filter_get_happy_path)
{
	struct stream_sink ram_sink = {0};
	uint8_t cek_key_id_cbor[] = {
		0x1A, 0x00, 0x00, 0x00, 0x00,
	};

	get_cbor_key_id(KEY_ID_FWENC_APPLICATION_GEN1, cek_key_id_cbor, sizeof(cek_key_id_cbor));

	struct suit_encryption_info enc_info = {
		.enc_alg_id = suit_cose_aes256_gcm,
		.IV = {
				.value = iv_direct,
				.len = sizeof(iv_direct),
			},
		.aad = {
				.value = aad,
				.len = strlen(aad),
			},
		.kw_alg_id = suit_cose_direct,
		.kw_key.direct = {.key_id = {.value = cek_key_id_cbor,
			       .len = sizeof(cek_key_id_cbor)},}
	};

	ram_sink.write = write_ram;
	ram_sink.used_storage = used_storage;
	suit_mci_fw_encryption_key_id_validate_fake.return_val = SUIT_PLAT_SUCCESS;
	suit_plat_decode_key_id_fake.return_val = SUIT_PLAT_SUCCESS;
	psa_aead_decrypt_setup_fake.return_val = PSA_SUCCESS;
	psa_aead_set_nonce_fake.return_val = PSA_SUCCESS;
	psa_aead_update_ad_fake.return_val = PSA_SUCCESS;
	
	suit_plat_err_t err = suit_decrypt_filter_get(&dec_sink, &enc_info, &sample_class_id, &ram_sink);
	zassert_equal(err, SUIT_PLAT_SUCCESS,
		      "Incorrect error code when getting decrypt filter");

	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.call_count, 1,
		      "Invalid number of calls to suit_mci_fw_encryption_key_id_validate");
	zassert_equal_ptr(suit_mci_fw_encryption_key_id_validate_fake.arg0_val, &sample_class_id,
			   "Invalid class ID passed to suit_mci_fw_encryption_key_id_validate");
	zassert_equal(psa_aead_decrypt_setup_fake.call_count, 1,
			 "Invalid number of calls to psa_aead_decrypt_setup");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg1_val, iv_direct,
			 "Invalid IV passed to psa_aead_set_nonce");
	zassert_equal_ptr(psa_aead_set_nonce_fake.arg2_val, sizeof(iv_direct),
			 "Invalid IV length passed to psa_aead_set_nonce");
	zassert_equal(psa_aead_set_nonce_fake.call_count, 1,
			"Invalid number of calls to psa_aead_set_nonce");
	zassert_equal(psa_aead_update_ad_fake.call_count, 1,
			"Invalid number of calls to psa_aead_update_ad");
	zassert_equal_ptr(psa_aead_update_ad_fake.arg1_val, aad,
			 "Invalid ad passed to psa_aead_update_ad");
	zassert_equal_ptr(psa_aead_update_ad_fake.arg2_val, strlen(aad),
			 "Invalid ad length passed to psa_aead_update_ad");
	zassert_equal(psa_aead_abort_fake.call_count, 0,
			"Invalid number of calls to psa_aead_abort");
	zassert_not_equal(   dec_sink.ctx && dec_sink.write && dec_sink.erase
					  && dec_sink.release && dec_sink.flush && dec_sink.used_storage, NULL,
			"Invalid dec_sink.ctx value");
}
