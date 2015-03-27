/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <compiler.h>
#include <tee/entry.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/tee_dispatch.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>

#include <assert.h>

#define SHM_CACHE_ATTRS	\
	(uint32_t)(core_mmu_is_shm_cached() ?  OPTEE_SMC_SHM_CACHED : 0)

static bool copy_in_params(const struct optee_msg_param *params,
		uint32_t num_params, uint32_t *param_types,
		uint32_t param_attr[TEE_NUM_PARAMS],
		TEE_Param tee_params[TEE_NUM_PARAMS])
{
	size_t n;
	uint8_t pt[4];
	uint32_t cache_attr;
	uint32_t attr;

	*param_types = 0;

	if (num_params > TEE_NUM_PARAMS)
		return false;

	for (n = 0; n < num_params; n++) {
		if (params[n].attr & OPTEE_MSG_ATTR_META)
			return false;
		if (params[n].attr & OPTEE_MSG_ATTR_FRAGMENT)
			return false;

		attr = params[n].attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			pt[n] = TEE_PARAM_TYPE_NONE;
			param_attr[n] = 0;
			memset(tee_params + n, 0, sizeof(TEE_Param));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			pt[n] = TEE_PARAM_TYPE_VALUE_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			param_attr[n] = 0;
			tee_params[n].value.a = params[n].u.value.a;
			tee_params[n].value.b = params[n].u.value.b;
			break;
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			cache_attr =
				(params[n].attr >> OPTEE_MSG_ATTR_CACHE_SHIFT) &
				OPTEE_MSG_ATTR_CACHE_MASK;
			if (cache_attr == OPTEE_MSG_ATTR_CACHE_PREDEFINED)
				param_attr[n] = SHM_CACHE_ATTRS;
			else
				return false;
			tee_params[n].memref.buffer =
				(void *)(uintptr_t)params[n].u.tmem.buf_ptr;
			tee_params[n].memref.size = params[n].u.tmem.size;
			break;
		default:
			return false;
		}
	}
	for (; n < TEE_NUM_PARAMS; n++) {
		pt[n] = TEE_PARAM_TYPE_NONE;
		param_attr[n] = 0;
		tee_params[n].value.a = 0;
		tee_params[n].value.b = 0;
	}

	*param_types = TEE_PARAM_TYPES(pt[0], pt[1], pt[2], pt[3]);

	return true;
}

static void copy_out_param(const TEE_Param tee_params[TEE_NUM_PARAMS],
		uint32_t param_types, uint32_t num_params,
		struct optee_msg_param *params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[n].u.tmem.size = tee_params[n].memref.size;
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].u.value.a = tee_params[n].value.a;
			params[n].u.value.b = tee_params[n].value.b;
			break;
		default:
			break;
		}
	}
}

/*
 * Extracts mandatory parameter for open session.
 *
 * Returns
 * false : mandatory parameter wasn't found or malformatted
 * true  : paramater found and OK
 */
static bool get_open_session_meta(struct optee_msg_arg *arg,
		uint32_t num_params, size_t *num_meta,
		TEE_UUID *uuid, TEE_Identity *clnt_id)
{
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);
	const uint32_t req_attr = OPTEE_MSG_ATTR_META |
				  OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;

	if (num_params < (*num_meta + 2))
		return false;

	if (params[*num_meta].attr != req_attr ||
	    params[*num_meta + 1].attr != req_attr)
		return false;

	memcpy(uuid, &params[*num_meta].u.value, sizeof(TEE_UUID));
	memcpy(&clnt_id->uuid, &params[*num_meta + 1].u.value,
	       sizeof(TEE_UUID));
	clnt_id->login = params[*num_meta + 1].u.value.c;

	(*num_meta) += 2;
	return true;
}

static void entry_open_session(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{
	struct tee_dispatch_open_session_in in;
	struct tee_dispatch_open_session_out out;
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);
	size_t num_meta = 0;

	if (!get_open_session_meta(arg, num_params, &num_meta, &in.uuid,
				   &in.clnt_id))
		goto bad_params;

	if (!copy_in_params(params + num_meta, num_params - num_meta,
			    &in.param_types, in.param_attr, in.params))
		goto bad_params;

	(void)tee_dispatch_open_session(&in, &out);

	copy_out_param(out.params, in.param_types, num_params - num_meta,
		       params + num_meta);

	arg->session = (vaddr_t)out.sess;
	arg->ret = out.msg.res;
	arg->ret_origin = out.msg.err;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
	return;

bad_params:
	DMSG("Bad params");
	arg->ret = TEE_ERROR_BAD_PARAMETERS;
	arg->ret_origin = TEE_ORIGIN_TEE;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_close_session(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{

	if (num_params == 0) {
		struct tee_close_session_in in;

		in.sess = (TEE_Session *)(uintptr_t)arg->session;
		arg->ret = tee_dispatch_close_session(&in);
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
	}

	arg->ret_origin = TEE_ORIGIN_TEE;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_invoke_command(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{
	struct tee_dispatch_invoke_command_in in;
	struct tee_dispatch_invoke_command_out out;
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);

	if (!copy_in_params(params, num_params,
			 &in.param_types, in.param_attr, in.params)) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		return;
	}

	in.sess = (TEE_Session *)(vaddr_t)arg->session;
	in.cmd = arg->func;
	(void)tee_dispatch_invoke_command(&in, &out);

	copy_out_param(out.params, in.param_types, num_params, params);

	arg->ret = out.msg.res;
	arg->ret_origin = out.msg.err;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_cancel(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{

	if (num_params == 0) {
		struct tee_dispatch_cancel_command_in in;
		struct tee_dispatch_cancel_command_out out;

		in.sess = (TEE_Session *)(vaddr_t)arg->session;
		(void)tee_dispatch_cancel_command(&in, &out);
		arg->ret = out.msg.res;
		arg->ret_origin = out.msg.err;
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
	}

	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}



static void tee_entry_call_with_arg(struct thread_smc_args *smc_args)
{
	paddr_t parg;
	struct optee_msg_arg *arg = NULL;	/* fix gcc warning */
	uint32_t num_params;

	parg = (uint64_t)smc_args->a1 << 32 | smc_args->a2;
	if (!tee_pbuf_is_non_sec(parg, sizeof(struct optee_msg_arg)) ||
	    !TEE_ALIGNMENT_IS_OK(parg, struct optee_msg_arg) ||
	    core_pa2va(parg, &arg)) {
		EMSG("Bad arg address 0x%" PRIxPA, parg);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADADDR;
		return;
	}

	num_params = arg->num_params;
	if (!tee_pbuf_is_non_sec(parg, OPTEE_MSG_GET_ARG_SIZE(num_params))) {
		EMSG("Bad arg address 0x%" PRIxPA, parg);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADADDR;
		return;
	}

	if (smc_args->a0 == OPTEE_SMC_CALL_WITH_ARG) {
		thread_set_irq(true);	/* Enable IRQ for STD calls */
		switch (arg->cmd) {
		case OPTEE_MSG_CMD_OPEN_SESSION:
			entry_open_session(smc_args, arg, num_params);
			break;
		case OPTEE_MSG_CMD_CLOSE_SESSION:
			entry_close_session(smc_args, arg, num_params);
			break;
		case OPTEE_MSG_CMD_INVOKE_COMMAND:
			entry_invoke_command(smc_args, arg, num_params);
			break;
		case OPTEE_MSG_CMD_CANCEL:
			entry_cancel(smc_args, arg, num_params);
			break;
		default:
			EMSG("Unknown cmd 0x%x\n", arg->cmd);
			smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		}
	} else {
		EMSG("Unknown fastcall cmd 0x%x\n", arg->cmd);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
	}
}

#if 0
static void tee_entry_register_shm(struct thread_smc_args *args)
{
#if 0
	switch (tee_mmu_register_shm(args->a1, args->a2, args->a3)) {
	case TEE_SUCCESS:
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		break;
	case TEE_ERROR_BAD_PARAMETERS:
		smc_args->a0 = OPTEE_SMC_RETURN_EBADADDR;
		break;
	case TEE_ERROR_BUSY:
		smc_args->a0 = OPTEE_SMC_RETURN_EBUSY;
		break;
	default:
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		break;
	}
#else
	EMSG("Unavailable smc 0x%" PRIx64, (uint64_t)args->a0);
	args->a0 = OPTEE_SMC_RETURN_EBADCMD;
#endif
}

static void tee_entry_unregister_shm(struct thread_smc_args *args)
{
	EMSG("Unavailable smc 0x%" PRIx64 , (uint64_t)args->a0);
	args->a0 = OPTEE_SMC_RETURN_EBADCMD;
}
#endif

static void tee_entry_get_shm_config(struct thread_smc_args *args)
{
	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = default_nsec_shm_paddr;
	args->a2 = default_nsec_shm_size;
	args->a3 = SHM_CACHE_ATTRS;
}

static void tee_entry_fastcall_l2cc_mutex(struct thread_smc_args *args)
{
	TEE_Result ret;

#ifdef ARM32
	switch (args->a1) {
	case OPTEE_SMC_L2CC_MUTEX_GET_ADDR:
		ret = tee_get_l2cc_mutex(&args->a2);
		break;
	case OPTEE_SMC_L2CC_MUTEX_SET_ADDR:
		ret = tee_set_l2cc_mutex(&args->a2);
		break;
	case OPTEE_SMC_L2CC_MUTEX_ENABLE:
		ret = tee_enable_l2cc_mutex();
		break;
	case OPTEE_SMC_L2CC_MUTEX_DISABLE:
		ret = tee_disable_l2cc_mutex();
		break;
	default:
		args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		return;
	}
#else
	ret = TEE_ERROR_NOT_SUPPORTED;
#endif
	if (ret == TEE_ERROR_NOT_SUPPORTED)
		args->a0 = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION;
	else if (ret)
		args->a0 = OPTEE_SMC_RETURN_EBADADDR;
	else
		args->a0 = OPTEE_SMC_RETURN_OK;
}

static void tee_entry_exchange_capabilities(struct thread_smc_args *args)
{
	if (args->a1) {
		/*
		 * Either unknown capability or
		 * OPTEE_SMC_NSEC_CAP_UNIPROCESSOR, in either case we can't
		 * deal with it.
		 */
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = OPTEE_SMC_SEC_CAP_HAVE_RESERVERED_SHM;
}

static void tee_entry_disable_shm_cache(struct thread_smc_args *args)
{
	bool is_empty;
	uint64_t cookie;

	if (!thread_disable_prealloc_rpc_cache(&is_empty, &cookie)) {
		args->a0 = OPTEE_SMC_RETURN_EBUSY;
		return;
	}

	if (is_empty) {
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = cookie >> 32;
	args->a2 = cookie;
}

static void tee_entry_enable_shm_cache(struct thread_smc_args *args)
{
	if (thread_enable_prealloc_rpc_cache())
		args->a0 = OPTEE_SMC_RETURN_OK;
	else
		args->a0 = OPTEE_SMC_RETURN_EBUSY;
}

void tee_entry(struct thread_smc_args *args)
{
	switch (args->a0) {
	case OPTEE_SMC_CALLS_COUNT:
		tee_entry_get_api_call_count(args);
		break;
	case OPTEE_SMC_CALLS_UID:
		tee_entry_get_api_uuid(args);
		break;
	case OPTEE_SMC_CALLS_REVISION:
		tee_entry_get_api_revision(args);
		break;
	case OPTEE_SMC_CALL_GET_OS_UUID:
		tee_entry_get_os_uuid(args);
		break;
	case OPTEE_SMC_CALL_GET_OS_REVISION:
		tee_entry_get_os_revision(args);
		break;
	case OPTEE_SMC_CALL_WITH_ARG:
		tee_entry_call_with_arg(args);
		break;
	case OPTEE_SMC_GET_SHM_CONFIG:
		tee_entry_get_shm_config(args);
		break;
	case OPTEE_SMC_L2CC_MUTEX:
		tee_entry_fastcall_l2cc_mutex(args);
		break;
#if 0
	case OPTEE_SMC_REGISTER_SHM:
		tee_entry_register_shm(args);
		break;
	case OPTEE_SMC_UNREGISTER_SHM:
		tee_entry_unregister_shm(args);
		break;
#endif
	case OPTEE_SMC_EXCHANGE_CAPABILITIES:
		tee_entry_exchange_capabilities(args);
		break;
	case OPTEE_SMC_DISABLE_SHM_CACHE:
		tee_entry_disable_shm_cache(args);
		break;
	case OPTEE_SMC_ENABLE_SHM_CACHE:
		tee_entry_enable_shm_cache(args);
		break;
	default:
		args->a0 = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION;
		break;
	}
}

size_t tee_entry_generic_get_api_call_count(void)
{
	/*
	 * All the different calls handled in this file. If the specific
	 * target has additional calls it will call this function and
	 * add the number of calls the target has added.
	 */
	return 9;
}

void __weak tee_entry_get_api_call_count(struct thread_smc_args *args)
{
	args->a0 = tee_entry_generic_get_api_call_count();
}

void __weak tee_entry_get_api_uuid(struct thread_smc_args *args)
{
	args->a0 = OPTEE_MSG_UID_0;
	args->a1 = OPTEE_MSG_UID_1;
	args->a2 = OPTEE_MSG_UID_2;
	args->a3 = OPTEE_MSG_UID_3;
}

void __weak tee_entry_get_api_revision(struct thread_smc_args *args)
{
	args->a0 = OPTEE_MSG_REVISION_MAJOR;
	args->a1 = OPTEE_MSG_REVISION_MINOR;
}

void __weak tee_entry_get_os_uuid(struct thread_smc_args *args)
{
	args->a0 = OPTEE_MSG_OS_OPTEE_UUID_0;
	args->a1 = OPTEE_MSG_OS_OPTEE_UUID_1;
	args->a2 = OPTEE_MSG_OS_OPTEE_UUID_2;
	args->a3 = OPTEE_MSG_OS_OPTEE_UUID_3;
}

void __weak tee_entry_get_os_revision(struct thread_smc_args *args)
{
	args->a0 = OPTEE_MSG_OS_OPTEE_REVISION_MAJOR;
	args->a1 = OPTEE_MSG_OS_OPTEE_REVISION_MINOR;
}
