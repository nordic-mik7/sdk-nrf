/*
 *  Copyright (c) 2021, PACKETCRAFT, INC.
 *
 *  SPDX-License-Identifier: LicenseRef-PCFT
 */

#include "audio_datapath.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <zephyr/zbus/zbus.h>
#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <nrfx_clock.h>
#include <contin_array.h>
#include <tone.h>
#include <pcm_mix.h>

#include "zbus_common.h"
#include "macros_common.h"
#include "led_assignments.h"
#include "led.h"
#include "audio_i2s.h"
#include "sw_codec_select.h"
#include "audio_system.h"
#include "streamctrl.h"
#include "sd_card_playback.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(audio_datapath, CONFIG_AUDIO_DATAPATH_LOG_LEVEL);

/*
 * Terminology
 *   - sample: signed integer of audio waveform amplitude
 *   - sample FIFO: circular array of raw audio samples
 *   - block: set of raw audio samples exchanged with I2S
 *   - frame: encoded audio packet exchanged with connectivity
 */

#define BLK_PERIOD_US 1000

/* Total sample FIFO period in microseconds */
#define FIFO_SMPL_PERIOD_US (CONFIG_AUDIO_MAX_PRES_DLY_US * 2)
#define FIFO_NUM_BLKS	    NUM_BLKS(FIFO_SMPL_PERIOD_US)
#define MAX_FIFO_SIZE	    (FIFO_NUM_BLKS * BLK_SIZE_SAMPLES(CONFIG_AUDIO_SAMPLE_RATE_HZ) * 2)

/* Number of audio blocks given a duration */
#define NUM_BLKS(d) ((d) / BLK_PERIOD_US)
/* Single audio block size in number of samples (stereo) */
/* clang-format off */
#define BLK_SIZE_SAMPLES(r) (((r)*BLK_PERIOD_US) / 1000000)
/* clang-format on */
/* Increment sample FIFO index by one block */
#define NEXT_IDX(i) (((i) < (FIFO_NUM_BLKS - 1)) ? ((i) + 1) : 0)
/* Decrement sample FIFO index by one block */
#define PREV_IDX(i) (((i) > 0) ? ((i) - 1) : (FIFO_NUM_BLKS - 1))

#define NUM_BLKS_IN_FRAME      NUM_BLKS(CONFIG_AUDIO_FRAME_DURATION_US)
#define BLK_MONO_NUM_SAMPS     BLK_SIZE_SAMPLES(CONFIG_AUDIO_SAMPLE_RATE_HZ)
#define BLK_STEREO_NUM_SAMPS   (BLK_MONO_NUM_SAMPS * 2)
/* Number of octets in a single audio block */
#define BLK_MONO_SIZE_OCTETS   (BLK_MONO_NUM_SAMPS * CONFIG_AUDIO_BIT_DEPTH_OCTETS)
#define BLK_STEREO_SIZE_OCTETS (BLK_MONO_SIZE_OCTETS * 2)
/* How many function calls before moving on with drift compensation */
#define DRIFT_COMP_WAITING_CNT (DRIFT_MEAS_PERIOD_US / BLK_PERIOD_US)
/* How much data to be collected before moving on with presentation compensation */
#define PRES_COMP_NUM_DATA_PTS (DRIFT_MEAS_PERIOD_US / CONFIG_AUDIO_FRAME_DURATION_US)

/* Audio clock - nRF5340 Analog Phase-Locked Loop (APLL) */
#define APLL_FREQ_MIN	 HFCLKAUDIO_12_165_MHZ
#define APLL_FREQ_CENTER HFCLKAUDIO_12_288_MHZ
#define APLL_FREQ_MAX	 HFCLKAUDIO_12_411_MHZ
/* Use nanoseconds to reduce rounding errors */
/* clang-format off */
#define APLL_FREQ_ADJ(t) (-((t)*1000) / 331)
/* clang-format on */

#define DRIFT_MEAS_PERIOD_US	   100000
#define DRIFT_ERR_THRESH_LOCK	   16
#define DRIFT_ERR_THRESH_UNLOCK	   32
/* To get smaller corrections */
#define DRIFT_REGULATOR_DIV_FACTOR 2

/* To allow BLE transmission and (host -> HCI -> controller) */
#define JUST_IN_TIME_TARGET_DLY_US 3000
#define JUST_IN_TIME_BOUND_US	   2500

/* How often to print under-run warning */
#define UNDERRUN_LOG_INTERVAL_BLKS 5000

NET_BUF_POOL_FIXED_DEFINE(pool_i2s_rx, FIFO_NUM_BLKS, BLK_STEREO_SIZE_OCTETS,
			  sizeof(struct audio_metadata), NULL);

enum drift_comp_state {
	DRIFT_STATE_INIT,   /* Waiting for data to be received */
	DRIFT_STATE_CALIB,  /* Calibrate and zero out local delay */
	DRIFT_STATE_OFFSET, /* Adjust I2S offset relative to SDU Reference */
	DRIFT_STATE_LOCKED  /* Drift compensation locked - Minor corrections */
};

static const char *const drift_comp_state_names[] = {
	"INIT",
	"CALIB",
	"OFFSET",
	"LOCKED",
};

enum pres_comp_state {
	PRES_STATE_INIT,  /* Initialize presentation compensation */
	PRES_STATE_MEAS,  /* Measure presentation delay */
	PRES_STATE_WAIT,  /* Wait for some time */
	PRES_STATE_LOCKED /* Presentation compensation locked */
};

static const char *const pres_comp_state_names[] = {
	"INIT",
	"MEAS",
	"WAIT",
	"LOCKED",
};

static struct {
	bool datapath_initialized;
	bool stream_started;
	void *decoded_data;

	struct {
		struct k_msgq *audio_q;
	} in;

	struct {
#if CONFIG_AUDIO_BIT_DEPTH_16
		int16_t __aligned(sizeof(uint32_t)) fifo[MAX_FIFO_SIZE];
#elif CONFIG_AUDIO_BIT_DEPTH_32
		int32_t __aligned(sizeof(uint32_t)) fifo[MAX_FIFO_SIZE];
#endif
		uint16_t prod_blk_idx; /* Output producer audio block index */
		uint16_t cons_blk_idx; /* Output consumer audio block index */
		uint32_t prod_blk_ts[FIFO_NUM_BLKS];
		/* Statistics */
		uint32_t total_blk_underruns;
	} out;

	uint32_t prev_drift_sdu_ref_us;
	uint32_t prev_pres_sdu_ref_us;
	uint32_t current_pres_dly_us;

	struct {
		enum drift_comp_state state: 8;
		uint16_t ctr; /* Count func calls. Used for waiting */
		uint32_t meas_start_time_us;
		uint32_t center_freq;
		bool enabled;
	} drift_comp;

	struct {
		enum pres_comp_state state: 8;
		uint16_t ctr; /* Count func calls. Used for collecting data points and waiting */
		int32_t sum_err_dly_us;
		uint32_t pres_delay_us;
		bool enabled;
	} pres_comp;
} ctrl_blk;

/**
 * @brief	Get the current number of blocks in the output buffer.
 */
static int filled_blocks_get(void)
{
	if (ctrl_blk.out.cons_blk_idx < ctrl_blk.out.prod_blk_idx) {
		return ctrl_blk.out.prod_blk_idx - ctrl_blk.out.cons_blk_idx;
	} else if (ctrl_blk.out.cons_blk_idx > ctrl_blk.out.prod_blk_idx) {
		return (FIFO_NUM_BLKS - ctrl_blk.out.cons_blk_idx) + ctrl_blk.out.prod_blk_idx;
	} else {
		return 0;
	}
}

static bool tone_active;
/* Buffer which can hold max 1 period test tone at 100 Hz */
static uint16_t test_tone_buf[CONFIG_AUDIO_SAMPLE_RATE_HZ / 100];
static size_t test_tone_size;

/**
 * @brief	Calculate error between sdu_ref and frame_start_ts_us.
 *
 * @note	Used to adjust audio clock to account for drift.
 *
 * @param	sdu_ref_us	Timestamp for SDU.
 * @param	frame_start_ts_us	Timestamp for I2S.
 *
 * @return	Error in microseconds (err_us).
 */
static int32_t err_us_calculate(uint32_t sdu_ref_us, uint32_t frame_start_ts_us)
{
	bool err_neg = false;

	int64_t total_err = ((int64_t)sdu_ref_us - (int64_t)frame_start_ts_us);

	/* Store sign for later use, since remainder operation is undefined for negatives */
	if (total_err < 0) {
		err_neg = true;
		total_err *= -1;
	}

	/* Check diff below 1000 us, diff above 1000 us is fixed later on */
	int32_t err_us = total_err % BLK_PERIOD_US;

	if (err_us > (BLK_PERIOD_US / 2)) {
		err_us = err_us - BLK_PERIOD_US;
	}

	/* Restore the sign */
	if (err_neg) {
		err_us *= -1;
	}

	return err_us;
}

static void hfclkaudio_set(uint16_t freq_value)
{
	uint16_t freq_val = freq_value;

	freq_val = MIN(freq_val, APLL_FREQ_MAX);
	freq_val = MAX(freq_val, APLL_FREQ_MIN);

	nrfx_clock_hfclkaudio_config_set(freq_val);
}

static void drift_comp_state_set(enum drift_comp_state new_state)
{
	if (new_state == ctrl_blk.drift_comp.state) {
		LOG_WRN("Trying to change to the same drift compensation state");
		return;
	}

	ctrl_blk.drift_comp.state = new_state;
	LOG_INF("Drft comp state: %s", drift_comp_state_names[new_state]);
}

/**
 * @brief	Adjust frequency of HFCLKAUDIO to get audio in sync.
 *
 * @note	The audio sync is based on sdu_ref_us.
 *
 * @param	frame_start_ts_us	I2S frame start timestamp.
 */
static void audio_datapath_drift_compensation(uint32_t frame_start_ts_us)
{
	if (CONFIG_AUDIO_DEV == HEADSET) {
		/** For headsets we do not use the timestamp gotten from hci_tx_sync_get to adjust
		 * for drift
		 */
		ctrl_blk.prev_drift_sdu_ref_us = ctrl_blk.prev_pres_sdu_ref_us;
	}
	switch (ctrl_blk.drift_comp.state) {
	case DRIFT_STATE_INIT: {
		/* Check if audio data has been received */
		if (ctrl_blk.prev_drift_sdu_ref_us) {
			ctrl_blk.drift_comp.meas_start_time_us = ctrl_blk.prev_drift_sdu_ref_us;

			drift_comp_state_set(DRIFT_STATE_CALIB);
		}

		break;
	}
	case DRIFT_STATE_CALIB: {
		if (++ctrl_blk.drift_comp.ctr < DRIFT_COMP_WAITING_CNT) {
			/* Waiting */
			return;
		}

		ctrl_blk.drift_comp.ctr = 0;

		int32_t err_us = DRIFT_MEAS_PERIOD_US - (ctrl_blk.prev_drift_sdu_ref_us -
							 ctrl_blk.drift_comp.meas_start_time_us);

		int32_t freq_adj = APLL_FREQ_ADJ(err_us);

		ctrl_blk.drift_comp.center_freq = APLL_FREQ_CENTER + freq_adj;

		if ((ctrl_blk.drift_comp.center_freq > (APLL_FREQ_MAX)) ||
		    (ctrl_blk.drift_comp.center_freq < (APLL_FREQ_MIN))) {
			LOG_DBG("Invalid center frequency, re-calculating");
			drift_comp_state_set(DRIFT_STATE_INIT);
			return;
		}

		hfclkaudio_set(ctrl_blk.drift_comp.center_freq);

		drift_comp_state_set(DRIFT_STATE_OFFSET);

		break;
	}
	case DRIFT_STATE_OFFSET: {
		if (++ctrl_blk.drift_comp.ctr < DRIFT_COMP_WAITING_CNT) {
			/* Waiting */
			return;
		}

		ctrl_blk.drift_comp.ctr = 0;

		int32_t err_us =
			err_us_calculate(ctrl_blk.prev_drift_sdu_ref_us, frame_start_ts_us);

		err_us /= DRIFT_REGULATOR_DIV_FACTOR;
		int32_t freq_adj = APLL_FREQ_ADJ(err_us);

		hfclkaudio_set(ctrl_blk.drift_comp.center_freq + freq_adj);

		if ((err_us < DRIFT_ERR_THRESH_LOCK) && (err_us > -DRIFT_ERR_THRESH_LOCK)) {
			drift_comp_state_set(DRIFT_STATE_LOCKED);
		}

		break;
	}
	case DRIFT_STATE_LOCKED: {
		if (++ctrl_blk.drift_comp.ctr < DRIFT_COMP_WAITING_CNT) {
			/* Waiting */
			return;
		}

		ctrl_blk.drift_comp.ctr = 0;

		int32_t err_us =
			err_us_calculate(ctrl_blk.prev_drift_sdu_ref_us, frame_start_ts_us);

		err_us /= DRIFT_REGULATOR_DIV_FACTOR;
		int32_t freq_adj = APLL_FREQ_ADJ(err_us);

		hfclkaudio_set(ctrl_blk.drift_comp.center_freq + freq_adj);

		if ((err_us > DRIFT_ERR_THRESH_UNLOCK) || (err_us < -DRIFT_ERR_THRESH_UNLOCK)) {
			drift_comp_state_set(DRIFT_STATE_INIT);
		}

		break;
	}
	default: {
		break;
	}
	}
}

static void pres_comp_state_set(enum pres_comp_state new_state)
{
	int ret;

	if (new_state == ctrl_blk.pres_comp.state) {
		return;
	}

	ctrl_blk.pres_comp.state = new_state;
	/* NOTE: The string below is used by the Nordic CI system */
	LOG_INF("Pres comp state: %s", pres_comp_state_names[new_state]);
	if (new_state == PRES_STATE_LOCKED) {
		ret = led_on(LED_AUDIO_SYNC_STATUS);
	} else {
		ret = led_off(LED_AUDIO_SYNC_STATUS);
	}
	ERR_CHK(ret);
}

/**
 * @brief	Move audio blocks back and forth in FIFO to get audio in sync.
 *
 * @note	The audio sync is based on sdu_ref_us.
 *
 * @param	recv_frame_ts_us	Timestamp of when frame was received.
 * @param	sdu_ref_us		ISO timestamp reference from Bluetooth LE controller.
 * @param	sdu_ref_not_consecutive	True if sdu_ref_us and the previous sdu_ref_us
 *					originate from non-consecutive frames.
 */
static void audio_datapath_presentation_compensation(uint32_t recv_frame_ts_us, uint32_t sdu_ref_us,
						     bool sdu_ref_not_consecutive)
{
	if (ctrl_blk.drift_comp.state != DRIFT_STATE_LOCKED) {
		/* Unconditionally reset state machine if drift compensation looses lock */
		pres_comp_state_set(PRES_STATE_INIT);
		return;
	}

	/* Move presentation compensation into PRES_STATE_WAIT if sdu_ref_us and
	 * the previous sdu_ref_us originate from non-consecutive frames.
	 */
	if (sdu_ref_not_consecutive) {
		ctrl_blk.pres_comp.ctr = 0;
		pres_comp_state_set(PRES_STATE_WAIT);
	}

	int32_t wanted_pres_dly_us =
		ctrl_blk.pres_comp.pres_delay_us - (recv_frame_ts_us - sdu_ref_us);
	int32_t pres_adj_us = 0;

	switch (ctrl_blk.pres_comp.state) {
	case PRES_STATE_INIT: {
		ctrl_blk.pres_comp.ctr = 0;
		ctrl_blk.pres_comp.sum_err_dly_us = 0;
		pres_comp_state_set(PRES_STATE_MEAS);

		break;
	}
	case PRES_STATE_MEAS: {
		if (ctrl_blk.pres_comp.ctr++ < PRES_COMP_NUM_DATA_PTS) {
			ctrl_blk.pres_comp.sum_err_dly_us +=
				wanted_pres_dly_us - ctrl_blk.current_pres_dly_us;

			/* Same state - Collect more data */
			break;
		}

		ctrl_blk.pres_comp.ctr = 0;

		pres_adj_us = ctrl_blk.pres_comp.sum_err_dly_us / PRES_COMP_NUM_DATA_PTS;
		if ((pres_adj_us >= (BLK_PERIOD_US / 2)) || (pres_adj_us <= -(BLK_PERIOD_US / 2))) {
			pres_comp_state_set(PRES_STATE_WAIT);
		} else {
			/* Drift compensation will always be in DRIFT_STATE_LOCKED here */
			pres_comp_state_set(PRES_STATE_LOCKED);
		}

		break;
	}
	case PRES_STATE_WAIT: {
		if (ctrl_blk.pres_comp.ctr++ >
		    (FIFO_SMPL_PERIOD_US / CONFIG_AUDIO_FRAME_DURATION_US)) {
			pres_comp_state_set(PRES_STATE_INIT);
		}

		break;
	}
	case PRES_STATE_LOCKED: {
		/*
		 * Presentation delay compensation moves into PRES_STATE_WAIT if sdu_ref_us
		 * and the previous sdu_ref_us originate from non-consecutive frames, or into
		 * PRES_STATE_INIT if drift compensation unlocks.
		 */

		break;
	}
	default: {
		break;
	}
	}

	if (pres_adj_us == 0) {
		return;
	}

	/* Operation to obtain nearest whole number in subsequent operations */
	if (pres_adj_us >= 0) {
		pres_adj_us += (BLK_PERIOD_US / 2);
	} else {
		pres_adj_us += -(BLK_PERIOD_US / 2);
	}

	/* Number of adjustment blocks is 0 as long as |pres_adj_us| < BLK_PERIOD_US */
	int32_t pres_adj_blks = pres_adj_us / BLK_PERIOD_US;

	if (pres_adj_blks > (FIFO_NUM_BLKS / 2)) {
		/* Limit adjustment */
		pres_adj_blks = FIFO_NUM_BLKS / 2;

		LOG_WRN("Requested presentation delay out of range: pres_adj_us=%d", pres_adj_us);
	} else if (pres_adj_blks < -(FIFO_NUM_BLKS / 2)) {
		/* Limit adjustment */
		pres_adj_blks = -(FIFO_NUM_BLKS / 2);

		LOG_WRN("Requested presentation delay out of range: pres_adj_us=%d", pres_adj_us);
	}

	if (pres_adj_blks > 0) {
		LOG_DBG("Presentation delay inserted: pres_adj_blks=%d", pres_adj_blks);

		/* Increase presentation delay */
		for (int i = 0; i < pres_adj_blks; i++) {
			/* Mute audio block */
			memset(&ctrl_blk.out.fifo[ctrl_blk.out.prod_blk_idx * BLK_STEREO_NUM_SAMPS],
			       0, BLK_STEREO_SIZE_OCTETS);

			/* Record producer block start reference */
			ctrl_blk.out.prod_blk_ts[ctrl_blk.out.prod_blk_idx] =
				recv_frame_ts_us - ((pres_adj_blks - i) * BLK_PERIOD_US);

			ctrl_blk.out.prod_blk_idx = NEXT_IDX(ctrl_blk.out.prod_blk_idx);
		}
	} else if (pres_adj_blks < 0) {
		LOG_DBG("Presentation delay removed: pres_adj_blks=%d", pres_adj_blks);

		/* Reduce presentation delay */
		for (int i = 0; i > pres_adj_blks; i--) {
			ctrl_blk.out.prod_blk_idx = PREV_IDX(ctrl_blk.out.prod_blk_idx);
		}
	}
}

static void tone_stop_worker(struct k_work *work)
{
	tone_active = false;
	memset(test_tone_buf, 0, sizeof(test_tone_buf));
	LOG_DBG("Tone stopped");
}

K_WORK_DEFINE(tone_stop_work, tone_stop_worker);

static void tone_stop_timer_handler(struct k_timer *dummy)
{
	k_work_submit(&tone_stop_work);
};

K_TIMER_DEFINE(tone_stop_timer, tone_stop_timer_handler, NULL);

int audio_datapath_tone_play(uint16_t freq, uint16_t dur_ms, float amplitude)
{
	int ret;

	if (tone_active) {
		return -EBUSY;
	}

	if (IS_ENABLED(CONFIG_AUDIO_TEST_TONE)) {
		ret = tone_gen(test_tone_buf, &test_tone_size, freq, CONFIG_AUDIO_SAMPLE_RATE_HZ,
			       amplitude);
		if (ret) {
			return ret;
		}
	} else {
		LOG_ERR("Test tone is not enabled");
		return -ENXIO;
	}

	/* If duration is 0, play forever */
	if (dur_ms != 0) {
		k_timer_start(&tone_stop_timer, K_MSEC(dur_ms), K_NO_WAIT);
	}

	tone_active = true;
	LOG_DBG("Tone started");
	return 0;
}

void audio_datapath_tone_stop(void)
{
	k_timer_stop(&tone_stop_timer);
	k_work_submit(&tone_stop_work);
}

static void tone_mix(uint8_t *tx_buf)
{
	int ret;
	int8_t tone_buf_continuous[BLK_MONO_SIZE_OCTETS];
	static uint32_t finite_pos;

	ret = contin_array_create(tone_buf_continuous, BLK_MONO_SIZE_OCTETS, test_tone_buf,
				  test_tone_size, &finite_pos);
	ERR_CHK(ret);

	ret = pcm_mix(tx_buf, BLK_STEREO_SIZE_OCTETS, tone_buf_continuous, BLK_MONO_SIZE_OCTETS,
		      B_MONO_INTO_A_STEREO_L);
	ERR_CHK(ret);
}

/* Alternate-buffers used when there is no active audio stream.
 * Used interchangeably by I2S.
 */
static struct {
	uint8_t __aligned(WB_UP(1)) buf_0[BLK_STEREO_SIZE_OCTETS];
	uint8_t __aligned(WB_UP(1)) buf_1[BLK_STEREO_SIZE_OCTETS];
	bool buf_0_in_use;
	bool buf_1_in_use;
} alt;

/**
 * @brief	Get first available alternative-buffer.
 *
 * @param	p_buffer	Double pointer to populate with buffer.
 *
 * @retval	0 if success.
 * @retval	-ENOMEM No available buffers.
 */
static int alt_buffer_get(void **p_buffer)
{
	if (!alt.buf_0_in_use) {
		alt.buf_0_in_use = true;
		*p_buffer = alt.buf_0;
	} else if (!alt.buf_1_in_use) {
		alt.buf_1_in_use = true;
		*p_buffer = alt.buf_1;
	} else {
		return -ENOMEM;
	}

	return 0;
}

/**
 * @brief	Checks if pointer matches that of a buffer
 *		and frees it in one operation.
 *
 * @param	p_buffer	Buffer to free.
 */
static void alt_buffer_free(void const *const p_buffer)
{
	if (p_buffer == alt.buf_0) {
		alt.buf_0_in_use = false;
	} else if (p_buffer == alt.buf_1) {
		alt.buf_1_in_use = false;
	}
}

/**
 * @brief	Frees both alternative buffers.
 */
static void alt_buffer_free_both(void)
{
	alt.buf_0_in_use = false;
	alt.buf_1_in_use = false;
}

/*
 * This handler function is called every time I2S needs new buffers for
 * TX and RX data.
 *
 * The new TX data buffer is the next consumer block in out.fifo.
 *
 * The new RX data buffer is the first empty slot of in.fifo.
 * New I2S RX data is located in rx_buf_released, and is locked into
 * the in.fifo message queue.
 */
static void audio_datapath_i2s_blk_complete(uint32_t frame_start_ts_us, uint32_t *rx_buf_released,
					    uint32_t const *tx_buf_released)
{
	int ret;
	static bool underrun_condition;

	alt_buffer_free(tx_buf_released);

	/*** Presentation delay measurement ***/
	ctrl_blk.current_pres_dly_us =
		frame_start_ts_us - ctrl_blk.out.prod_blk_ts[ctrl_blk.out.cons_blk_idx];

	/********** I2S TX **********/
	static uint8_t *tx_buf;

	if (IS_ENABLED(CONFIG_STREAM_BIDIRECTIONAL) || (CONFIG_AUDIO_DEV == HEADSET)) {
		if (tx_buf_released != NULL) {
			/* Double buffered index */
			uint32_t next_out_blk_idx = NEXT_IDX(ctrl_blk.out.cons_blk_idx);

			if (next_out_blk_idx != ctrl_blk.out.prod_blk_idx) {
				/* Only increment if not in under-run condition */
				ctrl_blk.out.cons_blk_idx = next_out_blk_idx;
				if (underrun_condition) {
					underrun_condition = false;
					LOG_WRN("Data received, total under-runs: %d",
						ctrl_blk.out.total_blk_underruns);
				}

				tx_buf = (uint8_t *)&ctrl_blk.out
						 .fifo[next_out_blk_idx * BLK_STEREO_NUM_SAMPS];

			} else {
				if (stream_state_get() == STATE_STREAMING) {
					underrun_condition = true;
					ctrl_blk.out.total_blk_underruns++;

					if ((ctrl_blk.out.total_blk_underruns %
					     UNDERRUN_LOG_INTERVAL_BLKS) == 0) {
						LOG_WRN("In I2S TX under-run condition, total: %d",
							ctrl_blk.out.total_blk_underruns);
					}
				}

				/*
				 * No data available in out.fifo
				 * use alternative buffers
				 */
				ret = alt_buffer_get((void **)&tx_buf);
				ERR_CHK(ret);

				memset(tx_buf, 0, BLK_STEREO_SIZE_OCTETS);
			}

			if (tone_active) {
				tone_mix(tx_buf);
			}
		}
	}

	/********** I2S RX **********/
	static int prev_ret;
	struct net_buf *rx_audio_block = NULL;

	if (IS_ENABLED(CONFIG_STREAM_BIDIRECTIONAL) || (CONFIG_AUDIO_DEV == GATEWAY)) {
		if (rx_buf_released == NULL) {
			/* No RX data available */
			ERR_CHK_MSG(-ENOMEM, "No RX data available");
		}

		if (k_msgq_num_free_get(ctrl_blk.in.audio_q) == 0 || pool_i2s_rx.avail_count == 0) {
			ret = -ENOMEM;
		} else {
			ret = 0;
		}

		/* If RX FIFO is filled up */
		if (ret == -ENOMEM) {
			struct net_buf *stale_i2s_data;

			if (ret != prev_ret) {
				LOG_WRN("I2S RX overrun. Single msg");
				prev_ret = ret;
			}

			ret = k_msgq_get(ctrl_blk.in.audio_q, (void *)&stale_i2s_data, K_NO_WAIT);
			ERR_CHK(ret);

			net_buf_unref(stale_i2s_data);

		} else if (ret == 0 && prev_ret == -ENOMEM) {
			LOG_WRN("I2S RX continuing stream");
			prev_ret = ret;
		}

		rx_audio_block = net_buf_alloc(&pool_i2s_rx, K_NO_WAIT);
		if (rx_audio_block == NULL) {
			ERR_CHK_MSG(-ENOMEM, "Out of RX buffers for I2S");
		}

		/* Store RX buffer in net_buf */
		net_buf_add_mem(rx_audio_block, rx_buf_released, BLK_STEREO_SIZE_OCTETS);

		struct audio_metadata *meta = net_buf_user_data(rx_audio_block);

		/* Add meta data */
		meta->data_coding = PCM;
		meta->data_len_us = 1000;
		meta->sample_rate_hz = CONFIG_AUDIO_SAMPLE_RATE_HZ;
		meta->bits_per_sample = CONFIG_AUDIO_BIT_DEPTH_BITS;
		meta->carried_bits_per_sample = CONFIG_AUDIO_BIT_DEPTH_BITS;
		meta->locations = BT_AUDIO_LOCATION_FRONT_LEFT | BT_AUDIO_LOCATION_FRONT_RIGHT;
		meta->bad_data = false;

		ret = k_msgq_put(ctrl_blk.in.audio_q, (void *)&rx_audio_block, K_NO_WAIT);
		ERR_CHK_MSG(ret, "Unable to put RX audio block into queue");
	}

	/*** Data exchange ***/
	audio_i2s_set_next_buf(tx_buf, rx_buf_released);

	/*** Drift compensation ***/
	if (ctrl_blk.drift_comp.enabled) {
		audio_datapath_drift_compensation(frame_start_ts_us);
	}
}

static void audio_datapath_i2s_start(void)
{
	/* Double buffer I2S */
	uint8_t *tx_buf_0 = NULL;
	uint8_t *tx_buf_1 = NULL;

	/* Buffers used for I2S RX. Used interchangeably by I2S. */
	static uint32_t rx_buf_0[BLK_STEREO_SIZE_OCTETS];
	static uint32_t rx_buf_1[BLK_STEREO_SIZE_OCTETS];

	/* TX */
	if (IS_ENABLED(CONFIG_STREAM_BIDIRECTIONAL) || (CONFIG_AUDIO_DEV == HEADSET)) {
		ctrl_blk.out.cons_blk_idx = PREV_IDX(ctrl_blk.out.cons_blk_idx);
		tx_buf_0 = (uint8_t *)&ctrl_blk.out
				     .fifo[ctrl_blk.out.cons_blk_idx * BLK_STEREO_NUM_SAMPS];

		ctrl_blk.out.cons_blk_idx = PREV_IDX(ctrl_blk.out.cons_blk_idx);
		tx_buf_1 = (uint8_t *)&ctrl_blk.out
				     .fifo[ctrl_blk.out.cons_blk_idx * BLK_STEREO_NUM_SAMPS];
	}

	/* Start I2S */
	audio_i2s_start(tx_buf_0, rx_buf_0);
	audio_i2s_set_next_buf(tx_buf_1, rx_buf_1);
}

static void audio_datapath_i2s_stop(void)
{
	audio_i2s_stop();
	alt_buffer_free_both();
}

/**
 * @brief	Adjust timing to make sure audio data is sent just in time for Bluetooth LE event.
 *
 * @note	The time from last anchor point is checked and then blocks of 1 ms can be dropped
 *		to allow the sending of encoded data to be sent just before the connection interval
 *		opens up. This is done to reduce overall latency.
 *
 * @param[in]	tx_sync_ts_us	The timestamp from get_tx_sync.
 * @param[in]	curr_ts_us	The current time. This must be in the controller frame of reference.
 */
static void audio_datapath_just_in_time_check_and_adjust(uint32_t tx_sync_ts_us,
							 uint32_t curr_ts_us)
{
	int ret;
	static int32_t print_count;
	int64_t diff;

	diff = (int64_t)tx_sync_ts_us - curr_ts_us;

	/*
	 * The diff should always be positive. If diff is a large negative number, it is likely
	 * that wrapping has occurred. A small negative value however, may point to the application
	 * sending data too late, and we need to drop data to get back in sync with the controller.
	 */
	if (diff < -((int64_t)UINT32_MAX / 2)) {
		LOG_DBG("Timestamp wrap. diff: %lld", diff);
		diff += UINT32_MAX;

	} else if (diff < 0) {
		LOG_DBG("tx_sync_ts_us: %u is earlier than curr_ts_us %u", tx_sync_ts_us,
			curr_ts_us);
	}

	if (print_count % 100 == 0) {
		LOG_DBG("JIT diff: %lld us. Target: %u +/- %u", diff, JUST_IN_TIME_TARGET_DLY_US,
			JUST_IN_TIME_BOUND_US);
	}
	print_count++;

	if ((diff < (JUST_IN_TIME_TARGET_DLY_US - JUST_IN_TIME_BOUND_US)) ||
	    (diff > (JUST_IN_TIME_TARGET_DLY_US + JUST_IN_TIME_BOUND_US))) {
		ret = audio_system_fifo_rx_block_drop();
		if (ret) {
			LOG_WRN("Not able to drop FIFO RX block");
			return;
		}
		LOG_DBG("Dropped block to align with connection interval");
		print_count = 0;
	}
}

/**
 * @brief	Update sdu_ref_us so that drift compensation can work correctly.
 *
 * @note	This function is only valid for gateway using I2S as audio source
 *		and unidirectional audio stream (gateway to one or more headsets).
 *
 * @param	sdu_ref_us    ISO timestamp reference from Bluetooth LE controller.
 * @param	adjust        Indicate if the sdu_ref should be used to adjust timing.
 */
static void audio_datapath_sdu_ref_update(const struct zbus_channel *chan)
{
	if (IS_ENABLED(CONFIG_AUDIO_SOURCE_I2S)) {
		uint32_t tx_sync_ts_us;
		uint32_t curr_ts_us;
		bool adjust;
		const struct sdu_ref_msg *msg;

		msg = zbus_chan_const_msg(chan);
		tx_sync_ts_us = msg->tx_sync_ts_us;
		curr_ts_us = msg->curr_ts_us;
		adjust = msg->adjust;

		if (ctrl_blk.stream_started) {
			ctrl_blk.prev_drift_sdu_ref_us = tx_sync_ts_us;

			if (adjust && tx_sync_ts_us != 0) {
				audio_datapath_just_in_time_check_and_adjust(tx_sync_ts_us,
									     curr_ts_us);
			}
		} else {
			LOG_WRN("Stream not started - Can not update tx_sync_ts_us");
		}
	}
}

ZBUS_LISTENER_DEFINE(sdu_ref_msg_listen, audio_datapath_sdu_ref_update);

int audio_datapath_pres_delay_us_set(uint32_t delay_us)
{
	if (!IN_RANGE(delay_us, CONFIG_AUDIO_MIN_PRES_DLY_US, CONFIG_AUDIO_MAX_PRES_DLY_US)) {
		LOG_WRN("Presentation delay not supported: %d us", delay_us);
		LOG_WRN("Keeping current value: %d us", ctrl_blk.pres_comp.pres_delay_us);
		return -EINVAL;
	}

	ctrl_blk.pres_comp.pres_delay_us = delay_us;

	LOG_DBG("Presentation delay set to %d us", delay_us);

	return 0;
}

void audio_datapath_pres_delay_us_get(uint32_t *delay_us)
{
	*delay_us = ctrl_blk.pres_comp.pres_delay_us;
}

void audio_datapath_stream_out(struct net_buf *audio_frame)
{
	if (!ctrl_blk.stream_started) {
		LOG_WRN("Stream not started");
		return;
	}

	if (audio_frame == NULL) {
		LOG_ERR("Buffer pointer is NULL");
	}

	/*** Check incoming data ***/
	struct audio_metadata *meta = net_buf_user_data(audio_frame);

	if (meta->ref_ts_us == ctrl_blk.prev_pres_sdu_ref_us && meta->ref_ts_us != 0) {
		LOG_WRN("Duplicate sdu_ref_us (%d) - Dropping audio frame", meta->ref_ts_us);
		return;
	}

	bool sdu_ref_not_consecutive = false;

	if (ctrl_blk.prev_pres_sdu_ref_us) {
		uint32_t sdu_ref_delta_us = meta->ref_ts_us - ctrl_blk.prev_pres_sdu_ref_us;

		/* Check if the delta is from two consecutive frames */
		if (sdu_ref_delta_us <
		    (CONFIG_AUDIO_FRAME_DURATION_US + (CONFIG_AUDIO_FRAME_DURATION_US / 2))) {
			/* Check for invalid delta */
			if ((sdu_ref_delta_us >
			     (CONFIG_AUDIO_FRAME_DURATION_US + SDU_REF_CH_DELTA_MAX_US)) ||
			    (sdu_ref_delta_us <
			     (CONFIG_AUDIO_FRAME_DURATION_US - SDU_REF_CH_DELTA_MAX_US))) {
				LOG_DBG("Invalid sdu_ref_us delta (%d) - Estimating sdu_ref_us",
					sdu_ref_delta_us);

				/* Estimate sdu_ref_us */
				meta->ref_ts_us = ctrl_blk.prev_pres_sdu_ref_us +
						  CONFIG_AUDIO_FRAME_DURATION_US;
			}
		} else {
			LOG_INF("sdu_ref_us not from consecutive frames (diff: %d us)",
				sdu_ref_delta_us);
			sdu_ref_not_consecutive = true;
		}
	}

	ctrl_blk.prev_pres_sdu_ref_us = meta->ref_ts_us;

	/*** Presentation compensation ***/
	if (ctrl_blk.pres_comp.enabled) {
		audio_datapath_presentation_compensation(meta->data_rx_ts_us, meta->ref_ts_us,
							 sdu_ref_not_consecutive);
	}

	/*** Decode ***/

	int ret;
	size_t pcm_size;

	ret = sw_codec_decode(audio_frame, &ctrl_blk.decoded_data, &pcm_size);
	if (ret) {
		LOG_WRN("SW codec decode error: %d", ret);
	}

	if (IS_ENABLED(CONFIG_SD_CARD_PLAYBACK)) {
		if (sd_card_playback_is_active()) {
			sd_card_playback_mix_with_stream(ctrl_blk.decoded_data, pcm_size);
		}
	}

	if (pcm_size != (BLK_STEREO_SIZE_OCTETS * NUM_BLKS_IN_FRAME)) {
		LOG_WRN("Decoded audio has wrong size: %d. Expected: %d", pcm_size,
			(BLK_STEREO_SIZE_OCTETS * NUM_BLKS_IN_FRAME));
		/* Discard frame */
		return;
	}

	/*** Add audio data to FIFO buffer ***/
	uint32_t num_blks_in_fifo = filled_blocks_get();

	if ((num_blks_in_fifo + NUM_BLKS_IN_FRAME) > FIFO_NUM_BLKS) {
		LOG_WRN("Output audio stream overrun - Discarding audio frame");

		/* Discard frame to allow consumer to catch up */
		return;
	}

	uint32_t out_blk_idx = ctrl_blk.out.prod_blk_idx;

	for (uint32_t i = 0; i < NUM_BLKS_IN_FRAME; i++) {
		if (IS_ENABLED(CONFIG_AUDIO_BIT_DEPTH_16)) {
			memcpy(&ctrl_blk.out.fifo[out_blk_idx * BLK_STEREO_NUM_SAMPS],
			       &((int16_t *)ctrl_blk.decoded_data)[i * BLK_STEREO_NUM_SAMPS],
			       BLK_STEREO_SIZE_OCTETS);
		} else if (IS_ENABLED(CONFIG_AUDIO_BIT_DEPTH_32)) {
			memcpy(&ctrl_blk.out.fifo[out_blk_idx * BLK_STEREO_NUM_SAMPS],
			       &((int32_t *)ctrl_blk.decoded_data)[i * BLK_STEREO_NUM_SAMPS],
			       BLK_STEREO_SIZE_OCTETS);
		}

		/* Record producer block start reference */
		ctrl_blk.out.prod_blk_ts[out_blk_idx] = meta->data_rx_ts_us + (i * BLK_PERIOD_US);

		out_blk_idx = NEXT_IDX(out_blk_idx);
	}

	ctrl_blk.out.prod_blk_idx = out_blk_idx;
}

int audio_datapath_start(struct k_msgq *audio_q_rx)
{
	__ASSERT_NO_MSG(audio_q_rx != NULL);

	if (!ctrl_blk.datapath_initialized) {
		LOG_WRN("Audio datapath not initialized");
		return -ECANCELED;
	}

	if (!ctrl_blk.stream_started) {
		ctrl_blk.in.audio_q = audio_q_rx;

		/* Clear counters and mute initial audio */
		memset(&ctrl_blk.out, 0, sizeof(ctrl_blk.out));

		audio_datapath_i2s_start();
		ctrl_blk.stream_started = true;

		return 0;
	} else {
		return -EALREADY;
	}
}

int audio_datapath_stop(void)
{
	if (ctrl_blk.stream_started) {
		ctrl_blk.stream_started = false;
		audio_datapath_i2s_stop();
		ctrl_blk.prev_pres_sdu_ref_us = 0;
		ctrl_blk.prev_drift_sdu_ref_us = 0;

		pres_comp_state_set(PRES_STATE_INIT);

		return 0;
	} else {
		return -EALREADY;
	}
}

int audio_datapath_init(void)
{
	memset(&ctrl_blk, 0, sizeof(ctrl_blk));
	audio_i2s_blk_comp_cb_register(audio_datapath_i2s_blk_complete);
	audio_i2s_init();
	ctrl_blk.datapath_initialized = true;
	ctrl_blk.drift_comp.enabled = true;
	ctrl_blk.pres_comp.enabled = true;

	if (IS_ENABLED(CONFIG_STREAM_BIDIRECTIONAL) && (CONFIG_AUDIO_DEV == GATEWAY)) {
		/* Disable presentation compensation feature for microphone return on gateway,
		 * since there's only one stream output from gateway for now, so no need to
		 * qhave presentation compensation.
		 */
		ctrl_blk.pres_comp.enabled = false;
	} else {
		ctrl_blk.pres_comp.enabled = true;
	}

	ctrl_blk.pres_comp.pres_delay_us = CONFIG_BT_AUDIO_PRESENTATION_DELAY_US;

	return 0;
}

static int cmd_i2s_tone_play(const struct shell *shell, size_t argc, const char **argv)
{
	int ret;
	uint16_t freq;
	uint16_t dur_ms;
	float amplitude;

	if (argc != 4) {
		shell_error(
			shell,
			"3 arguments (freq [Hz], dur [ms], and amplitude [0-1.0] must be provided");
		return -EINVAL;
	}

	if (!isdigit((int)argv[1][0])) {
		shell_error(shell, "Argument 1 is not numeric");
		return -EINVAL;
	}

	if (!isdigit((int)argv[2][0])) {
		shell_error(shell, "Argument 2 is not numeric");
		return -EINVAL;
	}

	freq = strtoul(argv[1], NULL, 10);
	dur_ms = strtoul(argv[2], NULL, 10);
	amplitude = strtof(argv[3], NULL);

	if (amplitude <= 0 || amplitude > 1) {
		shell_error(shell, "Make sure amplitude is 0 < [float] >= 1");
		return -EINVAL;
	}

	shell_print(shell, "Setting tone %d Hz for %d ms", freq, dur_ms);
	ret = audio_datapath_tone_play(freq, dur_ms, amplitude);

	if (ret == -EBUSY) {
		/* Abort continuous running tone with new tone */
		audio_datapath_tone_stop();
		ret = audio_datapath_tone_play(freq, dur_ms, amplitude);
	}

	if (ret) {
		shell_print(shell, "Tone failed with code %d", ret);
	}

	shell_print(shell, "Tone play: %d Hz for %d ms with amplitude %.02f", freq, dur_ms,
		    (double)amplitude);

	return ret;
}

static int cmd_i2s_tone_stop(const struct shell *shell, size_t argc, const char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	audio_datapath_tone_stop();

	shell_print(shell, "Tone stop");

	return 0;
}

static int cmd_hfclkaudio_drift_comp_enable(const struct shell *shell, size_t argc,
					    const char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ctrl_blk.drift_comp.enabled = true;

	shell_print(shell, "Audio PLL drift compensation enabled");

	return 0;
}

static int cmd_hfclkaudio_drift_comp_disable(const struct shell *shell, size_t argc,
					     const char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (ctrl_blk.pres_comp.enabled) {
		shell_print(shell, "Pres comp must be disabled to disable drift comp");
	} else {
		ctrl_blk.drift_comp.enabled = false;
		ctrl_blk.drift_comp.ctr = 0;
		drift_comp_state_set(DRIFT_STATE_INIT);

		shell_print(shell, "Audio PLL drift compensation disabled");
	}

	return 0;
}

static int cmd_audio_pres_comp_enable(const struct shell *shell, size_t argc, const char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (ctrl_blk.drift_comp.enabled) {
		ctrl_blk.pres_comp.enabled = true;

		shell_print(shell, "Presentation compensation enabled");
	} else {
		shell_print(shell, "Drift comp must be enabled to enable pres comp");
	}

	return 0;
}

static int cmd_audio_pres_comp_disable(const struct shell *shell, size_t argc, const char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ctrl_blk.pres_comp.enabled = false;
	pres_comp_state_set(PRES_STATE_INIT);

	shell_print(shell, "Presentation compensation disabled");

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(test_cmd,
			       SHELL_COND_CMD(CONFIG_SHELL, nrf_tone_start, NULL,
					      "Start local tone from nRF5340", cmd_i2s_tone_play),
			       SHELL_COND_CMD(CONFIG_SHELL, nrf_tone_stop, NULL,
					      "Stop local tone from nRF5340", cmd_i2s_tone_stop),
			       SHELL_COND_CMD(CONFIG_SHELL, pll_drift_comp_enable, NULL,
					      "Enable audio PLL auto drift compensation (default)",
					      cmd_hfclkaudio_drift_comp_enable),
			       SHELL_COND_CMD(CONFIG_SHELL, pll_drift_comp_disable, NULL,
					      "Disable audio PLL auto drift compensation",
					      cmd_hfclkaudio_drift_comp_disable),
			       SHELL_COND_CMD(CONFIG_SHELL, pll_pres_comp_enable, NULL,
					      "Enable audio presentation compensation (default)",
					      cmd_audio_pres_comp_enable),
			       SHELL_COND_CMD(CONFIG_SHELL, pll_pres_comp_disable, NULL,
					      "Disable audio presentation compensation",
					      cmd_audio_pres_comp_disable),
			       SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(test, &test_cmd, "Test mode commands", NULL);
