/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm.h>
#include <kernel/static_ta.h>
#include <kernel/user_ta.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <optee_msg_supplicant.h>
#include <pta_gprof.h>
#include <string.h>

static TEE_Result gprof_send_rpc(TEE_UUID *uuid, void *buf, size_t len,
				 uint32_t *id)
{
	struct optee_msg_param params[3];
	TEE_Result res = TEE_ERROR_GENERIC;
	uint64_t c = 0;
	paddr_t pa;
	char *va;

	thread_rpc_alloc_payload(sizeof(*uuid) + len, &pa, &c);
	if (!pa)
		return TEE_ERROR_OUT_OF_MEMORY;

	va = phys_to_virt(pa, MEM_AREA_NSEC_SHM);
	if (!va)
		goto exit;

	memcpy(va, uuid, sizeof(*uuid));
	memcpy(va + sizeof(*uuid), buf, len);

	memset(params, 0, sizeof(params));
	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INOUT;
	params[0].u.value.a = *id;

	params[1].attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	params[1].u.tmem.buf_ptr = pa;
	params[1].u.tmem.size = sizeof(*uuid);
	params[1].u.tmem.shm_ref = c;

	params[2].attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	params[2].u.tmem.buf_ptr = pa + sizeof(*uuid);
	params[2].u.tmem.size = len;
	params[2].u.tmem.shm_ref = c;

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_GPROF, 3, params);
	if (res != TEE_SUCCESS)
		goto exit;

	*id = (uint32_t)params[0].u.value.a;
exit:
	thread_rpc_free_payload(c);
	return res;
}

/* Return the TA session that invoked us through the TA-TA API */
static TEE_Result get_calling_session(struct tee_ta_session **s)
{
	TEE_Result res;

	res = tee_ta_get_current_session(s);
	if (res != TEE_SUCCESS)
		return res;
	*s = tee_ta_get_calling_session();
	return TEE_SUCCESS;
}

static TEE_Result gprof_send(uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct tee_ta_session *s;
	TEE_Result res;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_calling_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	return gprof_send_rpc(&s->ctx->uuid, params[1].memref.buffer,
			      params[1].memref.size, &params[0].value.a);
}

static TEE_Result gprof_start_pc_sampling(uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{

	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct tee_ta_session *s;
	struct sample_buf *sbuf;
	TEE_Result res;
	uint32_t len;
	uint32_t offset;
	uint32_t scale;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_calling_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	len = params[0].value.a;
	offset = params[0].value.b;
	scale = params[1].value.a;

	sbuf = calloc(1, sizeof(*sbuf));
	if (!sbuf)
		return TEE_ERROR_OUT_OF_MEMORY;

	sbuf->samples = calloc(1, len);
	if (!sbuf->samples) {
		free(sbuf);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	sbuf->nsamples = len/sizeof(*sbuf->samples);
	sbuf->offset = offset;
	sbuf->scale = scale;
	sbuf->freq = read_cntfrq();
	sbuf->enabled = true;
	s->sbuf = sbuf;

	return TEE_SUCCESS;
}

static TEE_Result gprof_stop_pc_sampling(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct tee_ta_session *s;
	struct sample_buf *sbuf;
	uint32_t outsize;
	TEE_Result res;
	uint32_t rate;
	uint32_t size;
	void *outbuf;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_calling_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	sbuf = s->sbuf;
	if (!sbuf)
		return TEE_ERROR_BAD_STATE;
	assert(sbuf->samples);

	/* Stop sampling */
	if (sbuf->enabled)
		sbuf->enabled = false;

	rate = ((uint64_t)sbuf->count * sbuf->freq) / sbuf->usr;
	params[1].value.a = rate;

	size = sbuf->nsamples * sizeof(*sbuf->samples);
	outbuf = params[0].memref.buffer;
	outsize = params[0].memref.size;
	if (!outbuf || !outsize) {
		params[0].memref.size = size;
		return TEE_SUCCESS;
	}

	if (outsize < size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(outbuf, sbuf->samples, size);

	DMSG("TA sampling stats: sample count=%" PRIu32 " user time=%" PRIu64
	     " cntfrq=%" PRIu32 " rate=%" PRIu32, sbuf->count, sbuf->usr,
	     sbuf->freq, rate);

	free(sbuf->samples);
	free(sbuf);
	s->sbuf = NULL;

	return TEE_SUCCESS;
}

static TEE_Result gprof_alloc(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct tee_ta_session *s;
	struct user_ta_ctx *utc;
	tee_mm_entry_t *mm;
	TEE_Result res;
	size_t size;
	paddr_t pa;
	vaddr_t va;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_calling_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	size = params[0].value.a;
	mm = tee_mm_alloc(&tee_mm_sec_ddr, size);
	if (!mm)
		return TEE_ERROR_OUT_OF_MEMORY;

	utc = to_user_ta_ctx(s->ctx);
	utc->mm_gprof_heap = mm;

	pa = tee_mm_get_smem(mm);
	va = tee_mmu_map_gprof_heap(utc, pa, size);

	tee_mmu_set_ctx(&utc->ctx);
	cache_maintenance_l1(DCACHE_AREA_CLEAN, (void *)va, size);
	cache_maintenance_l1(ICACHE_AREA_INVALIDATE, (void *)va, size);

	params[1].value.a = va & 0xFFFFFFFF;
#ifdef ARM64
	params[1].value.b = va >> 32;
#else
	params[1].value.b = 0;
#endif

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	TEE_Result res;
	struct tee_ta_session *s;

	/* Check that we're called from a TA */
	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;
	if (s->clnt_id.login != TEE_LOGIN_TRUSTED_APP)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static void close_session(void *sess_ctx __unused)
{
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_GPROF_SEND:
		return gprof_send(param_types, params);
	case PTA_GPROF_START_PC_SAMPLING:
		return gprof_start_pc_sampling(param_types, params);
	case PTA_GPROF_STOP_PC_SAMPLING:
		return gprof_stop_pc_sampling(param_types, params);
	case PTA_GPROF_ALLOC:
		return gprof_alloc(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static_ta_register(.uuid = PTA_GPROF_UUID, .name = "gprof",
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
