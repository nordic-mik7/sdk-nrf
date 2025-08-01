/*
 *  Copyright (c) 2023 Nordic Semiconductor ASA
 *
 *  SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "../include/sxsymcrypt/mac.h"
#include "../include/sxsymcrypt/keyref.h"
#include "../include/sxsymcrypt/cmmask.h"
#include <cracen/statuscodes.h>
#include "keyrefdefs.h"
#include "macdefs.h"
#include "crypmasterregs.h"
#include "hw.h"
#include "cmdma.h"
#include "cmaes.h"
#include <cracen/prng_pool.h>

int sx_mac_free(struct sxmac *c)
{
	int sx_err = SX_OK;
	if (c->key->clean_key) {
		sx_err = c->key->clean_key(c->key->user_data);
	}
	sx_cmdma_release_hw(&c->dma);
	return sx_err;
}

int sx_mac_hw_reserve(struct sxmac *c)
{
	int err = SX_OK;

	uint32_t prng_value;

	err = cracen_prng_value_from_pool(&prng_value);
	if (err != SX_OK) {
		return err;
	}

	sx_hw_reserve(&c->dma);

	err = sx_cm_load_mask(prng_value);
	if (err != SX_OK) {
		goto exit;
	}

	if (c->key->prepare_key) {
		err = c->key->prepare_key(c->key->user_data);
	}

exit:
	if (err != SX_OK) {
		return sx_handle_nested_error(sx_mac_free(c), err);
	}

	return SX_OK;
}

int sx_mac_feed(struct sxmac *c, const char *datain, size_t sz)
{
	if (!c->dma.hw_acquired) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}
	if (sz >= DMA_MAX_SZ) {
		return sx_handle_nested_error(sx_mac_free(c), SX_ERR_TOO_BIG);
	}
	if (c->cntindescs >= (ARRAY_SIZE(c->descs))) {
		return sx_handle_nested_error(sx_mac_free(c), SX_ERR_FEED_COUNT_EXCEEDED);
	}

	if (sz != 0) {
		ADD_RAW_INDESC(c->dma, datain, sz, c->cfg->dmatags->data);
		c->cntindescs++;
		c->feedsz += sz;
	}

	return SX_OK;
}

static int sx_mac_run(struct sxmac *c)
{
	if ((c->feedsz == 0) && (c->dma.dmamem.cfg & c->cfg->loadstate)) {
		return sx_handle_nested_error(sx_mac_free(c), SX_ERR_INPUT_BUFFER_TOO_SMALL);
	}
	sx_cmdma_start(&c->dma, sizeof(c->descs), c->descs);

	return SX_OK;
}

int sx_mac_generate(struct sxmac *c, char *mac)
{
	if (!c->dma.hw_acquired) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}

	if (c->feedsz == 0) {
		ADD_EMPTY_INDESC(c->dma, (c->cfg->cmdma_mask + 1), c->cfg->dmatags->data);
	}
	SET_LAST_DESC_IGN(c->dma, c->feedsz, c->cfg->cmdma_mask);

	ADD_OUTDESCA(c->dma, mac, c->macsz, c->cfg->cmdma_mask);

	c->dma.dmamem.cfg &= ~c->cfg->savestate;

	return sx_mac_run(c);
}

int sx_mac_resume_state(struct sxmac *c)
{
	int err;

	if (c->dma.hw_acquired) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}

	if (!c->cfg->statesz) {
		return SX_ERR_CONTEXT_SAVING_NOT_SUPPORTED;
	}

	/* Note that the sx_mac APIs are used only with CMAC at the moment so we always need to
	 * enable the AES countermeasures.
	 */
	err = sx_mac_hw_reserve(c);
	if (err != SX_OK) {
		return err;
	}

	sx_cmdma_newcmd(&c->dma, c->descs, c->dma.dmamem.cfg, c->cfg->dmatags->cfg);
	c->cntindescs = 1;
	if (KEYREF_IS_USR(c->key)) {
		ADD_CFGDESC(c->dma, c->key->key, c->key->sz, c->cfg->dmatags->key);
		c->cntindescs++;
	}
	ADD_INDESC_PRIV(c->dma, OFFSET_EXTRAMEM(c), c->cfg->statesz, c->cfg->dmatags->state);
	c->cntindescs++;
	c->dma.dmamem.cfg |= c->cfg->loadstate;
	c->feedsz = 0;

	return SX_OK;
}

int sx_mac_save_state(struct sxmac *c)
{
	uint32_t sz;

	if (!c->dma.hw_acquired) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}
	sz = c->feedsz;

	if (sz < c->cfg->blocksz) {
		return sx_handle_nested_error(sx_mac_free(c), SX_ERR_INPUT_BUFFER_TOO_SMALL);
	}
	if (sz % c->cfg->granularity) {
		return sx_handle_nested_error(sx_mac_free(c), SX_ERR_WRONG_SIZE_GRANULARITY);
	}

	c->dma.dmamem.cfg |= c->cfg->savestate;

	ADD_OUTDESC_PRIV(c->dma, OFFSET_EXTRAMEM(c), c->cfg->statesz, 0x0F);

	return sx_mac_run(c);
}

int sx_mac_status(struct sxmac *c)
{
	int r;

	if (!c->dma.hw_acquired) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}
	r = sx_cmdma_check();
	if (r == SX_ERR_HW_PROCESSING) {
		return r;
	}

#if CONFIG_DCACHE
	sys_cache_data_invd_range((void *)&c->extramem, sizeof(c->extramem));
#endif

	return sx_handle_nested_error(sx_mac_free(c), r);
}

int sx_mac_wait(struct sxmac *c)
{
	int r = SX_ERR_HW_PROCESSING;

	if (!c->dma.hw_acquired) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}

	while (r == SX_ERR_HW_PROCESSING) {
		r = sx_mac_status(c);
	}

	return r;
}
