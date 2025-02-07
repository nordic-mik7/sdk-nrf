/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SUIT_DECOMPRESS_FILTER_H__
#define SUIT_DECOMPRESS_FILTER_H__

#include <suit_sink.h>
#include <suit_types.h>
#include <suit_metadata.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get decompress filter object.
 * WARNING: decompression filter must be last in filter chain
 * 	because it needs to have an access to unaltered destination component memory
 *	during streaming.
 *
 * @param[out] in_sink   Pointer to input sink_stream to pass compressed data
 * @param[in]  compress_info  Pointer to the structure with compression info.
 * @param[in]  class_id  Pointer to the manifest class ID of the destination component
 * @param[in]  out_sink  Pointer to output sink_stream to be filled with decompressed data
 *
 * @return SUIT_PLAT_SUCCESS if success otherwise error code
 */
suit_plat_err_t suit_decompress_filter_get(struct stream_sink *in_sink,
					const struct suit_compression_info *compress_info,
					const suit_manifest_class_id_t *class_id,
					const struct stream_sink *out_sink);

#ifdef __cplusplus
}
#endif

#endif /* SUIT_DECOMPRESS_FILTER_H__ */
