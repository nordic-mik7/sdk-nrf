/*
 *  Copyright (c) 2023 Nordic Semiconductor ASA
 *
 *  SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "../include/sxsymcrypt/trng.h"
#include <cracen/statuscodes.h>
#include "crypmasterregs.h"
#include "hw.h"
#include "ba431regs.h"
#include "cmdma.h"
#include <security/cracen.h>

#ifndef RNG_CLKDIV
#define RNG_CLKDIV				(241)
#endif
#define RNG_OFF_TIMER_VAL	  (0)
#define RNG_INIT_WAIT_VAL	  (512)
#define RNG_NB_128BIT_BLOCKS	  (4)
#define RNG_FIFOLEVEL_GRANULARITY (4)
#define RNG_NO_OF_COND_KEYS	  (4)
/** Number of bytes per word used for test data, Version 0. Value is fixed in this version. */
#define RNG_BYTES_PER_WORD_V0 (4u)

#define RNG_RAW_MODE (BA431_FLD_Control_AIS31Bypass_MASK | \
			  BA431_FLD_Control_HealthTestBypass_MASK | \
			  BA431_FLD_Control_Conditioning_Bypass_MASK)

#if defined(CONFIG_CRACEN_HW_VERSION_LITE)
#define RNG_REPEATTHRESHOLD_VAL (21)
#define RNG_PROPTESTCUTOFF_VAL	(311)
#endif

static int ba431_check_state(void)
{
	uint32_t state = sx_rd_trng(BA431_REG_Status_OFST);

	state = (state & BA431_FLD_Status_State_MASK) >> BA431_FLD_Status_State_LSB;

	if (state == BA431_STATE_ERROR) {
		return SX_ERR_RESET_NEEDED;
	}

	if ((state == BA431_STATE_RESET) || (state == BA431_STATE_STARTUP)) {
		return SX_ERR_HW_PROCESSING;
	}

	return SX_OK;
}

static void sx_trng_enable(struct sx_trng *ctx)
{
	uint32_t ctrl_reg = sx_rd_trng(BA431_REG_Control_OFST);

	ctrl_reg |= BA431_FLD_Control_Enable_MASK;
	sx_wr_trng(BA431_REG_Control_OFST, ctrl_reg);
}

static void sx_trng_flush(void)
{
	uint32_t ctrl_reg = sx_rd_trng(BA431_REG_Control_OFST);

	sx_wr_trng(BA431_REG_Control_OFST, ctrl_reg | BA431_FLD_Control_SoftRst_MASK);
	sx_wr_trng(BA431_REG_Control_OFST, ctrl_reg & ~BA431_FLD_Control_SoftRst_MASK);
}

void sx_trng_restart(struct sx_trng *ctx)
{
	sx_trng_flush();
	sx_trng_enable(ctx);
}

int sx_trng_open(struct sx_trng *ctx, const struct sx_trng_config *config)
{
	int err;
	*ctx = (struct sx_trng){0};

	cracen_acquire();
	ctx->initialized = true;

	/* Trigger warm reset. This will have an effect if the engine was previously
	 * initialized. It will clear any data generated and stored in FIFOs, it will
	 * stop the ring oscillators and it will reset the internal state machine to
	 * "Reset" state.
	 */
	sx_trng_flush();

	uint32_t control;
	uint32_t fifo_wakeup_level;
	uint32_t rng_off_timer_val = RNG_OFF_TIMER_VAL;
	uint32_t rng_clkdiv = RNG_CLKDIV;
	uint32_t rng_init_wait_val = RNG_INIT_WAIT_VAL;
	uint32_t ctrlbitmask = 0;

	fifo_wakeup_level = sx_rd_trng(BA431_REG_FIFODepth_OFST) / RNG_FIFOLEVEL_GRANULARITY - 1;
	if (config) {
		if (config->wakeup_level) {
			if (config->wakeup_level > fifo_wakeup_level) {
				err = SX_ERR_TOO_BIG;
				goto error;
			}
			fifo_wakeup_level = config->wakeup_level;
		}
		if (config->off_time_delay) {
			rng_off_timer_val = config->off_time_delay;
		}
		if (config->init_wait) {
			rng_init_wait_val = config->init_wait;
		}
		if (config->sample_clock_div) {
			rng_clkdiv = config->sample_clock_div;
		}
		ctrlbitmask = config->control_bitmask;
	}

	/* Program powerdown and clock settings */
	sx_wr_trng(BA431_REG_FIFOThreshold_OFST, fifo_wakeup_level);
	sx_wr_trng(BA431_REG_SwOffTmrVal_OFST, rng_off_timer_val);
	sx_wr_trng(BA431_REG_ClkDiv_OFST, rng_clkdiv);
	sx_wr_trng(BA431_REG_InitWaitVal_OFST, rng_init_wait_val);

	/* CRACEN Lite has incorrect values for the TRNG tests. We update these here as a workaround
	 */
#if defined(CONFIG_CRACEN_HW_VERSION_LITE)
	sx_wr_trng(BA431_REG_REPEATTHRESHOLD, RNG_REPEATTHRESHOLD_VAL);
	sx_wr_trng(BA431_REG_PROPTHRESHOLD, RNG_PROPTESTCUTOFF_VAL);
#endif /* CONFIG_CRACEN_HW_VERSION_LITE */

	/* Configure the control register and set the enable bit */
	control = (RNG_NB_128BIT_BLOCKS << BA431_FLD_Control_Nb128BitBlocks_LSB);
	control |= ctrlbitmask;
	control |= BA431_FLD_Control_Enable_MASK;

	sx_wr_trng(BA431_REG_Control_OFST, control);

	return SX_OK;

error:
	cracen_release();
	ctx->initialized = false;
	return err;
}

static int ba431_setup_conditioning_key(struct sx_trng *ctx)
{
	uint32_t key;
	uint32_t level = sx_rd_trng(BA431_REG_FIFOLevel_OFST);

	/* FIFO level must be 4 (4 * 32bit Word) */
	if (level < RNG_NO_OF_COND_KEYS) {
		return SX_ERR_HW_PROCESSING;
	}

	for (size_t i = 0; i < RNG_NO_OF_COND_KEYS; i++) {
		key = sx_rd_trng(BA431_REG_FIFODATA_OFST);
		sx_wr_trng(BA431_REG_Key0_OFST + i * sizeof(key), key);
	}

	/* After the conditioning keys are written the FIFOs should be cleared
	 * as that data generated up to this point used default keys.
	 */
	sx_trng_restart(ctx);
	ctx->conditioning_key_set = 1;

	return SX_OK;
}

int sx_trng_get(struct sx_trng *ctx, char *dst, size_t size)
{
	int status = SX_OK;

	if (!ctx->initialized) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}

	status = ba431_check_state();
	if (status) {
		return status;
	}

	/* Program random key for the conditioning function */
	if (!ctx->conditioning_key_set) {
		status = ba431_setup_conditioning_key(ctx);
		if (status != SX_OK) {
			return status;
		}
	}

	/* Block sizes above the FIFO wakeup level to guarantee that the
	 * hardware will be able at some time to provide the requested bytes.
	 */
	uint32_t wakeup_level = sx_rd_trng(BA431_REG_FIFOThreshold_OFST);

	if (size > (wakeup_level + 1) * 16) {
		return SX_ERR_TOO_BIG;
	}

	uint32_t level = sx_rd_trng(BA431_REG_FIFOLevel_OFST);
	/* FIFO level in 4-byte words */
	if (size > level * RNG_FIFOLEVEL_GRANULARITY) {
		return SX_ERR_HW_PROCESSING;
	}

	while (size) {
		uint32_t data;

		data = sx_rd_trng(BA431_REG_FIFODATA_OFST);
		for (size_t i = 0; (i < sizeof(data)) && (size); i++, size--) {
			*dst = (char)(data & 0xFF);
			dst++;
			data >>= 8;
		}
	}

	return status;
}

int sx_trng_close(struct sx_trng *ctx)
{
	if (ctx->initialized) {
		cracen_release();
		ctx->initialized = false;
	}
	return SX_OK;
}

int sx_trng_save_state(struct sx_trng *ctx, struct sx_trng_state *state)
{
	state->conditioning_key_set = ctx->conditioning_key_set;

	if (ctx->conditioning_key_set) {
		for (size_t i = 0; i < RNG_NO_OF_COND_KEYS; i++) {
			state->cond_key[i] = sx_rd_trng(BA431_REG_Key0_OFST +
							i * sizeof(state->cond_key[0]));
		}
	}

	return SX_OK;
}


int sx_trng_restore_state(struct sx_trng *ctx,
	const struct sx_trng_config *config, const struct sx_trng_state *state)
{
	int status;

	status = sx_trng_open(ctx, config);
	if (status) {
		return status;
	}

	if (state->conditioning_key_set) {
		for (size_t i = 0; i < RNG_NO_OF_COND_KEYS; i++) {
			sx_wr_trng(BA431_REG_Key0_OFST + i * sizeof(state->cond_key[0]),
				   state->cond_key[i]);
		}
		sx_trng_restart(ctx);
		ctx->conditioning_key_set = 1;
	}

	return SX_OK;
}
