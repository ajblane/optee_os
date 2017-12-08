/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
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

#include <platform_config.h>

#include <arm.h>
#include <assert.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread_defs.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_fs_rpc.h>
#include <trace.h>
#include <util.h>

#include "thread_private.h"

#ifdef CFG_WITH_ARM_TRUSTED_FW
#define STACK_TMP_OFFS		0
#else
#define STACK_TMP_OFFS		SM_STACK_TMP_RESERVE_SIZE
#endif


#ifdef ARM32
#ifdef CFG_CORE_SANITIZE_KADDRESS
#define STACK_TMP_SIZE		(3072 + STACK_TMP_OFFS)
#else
#define STACK_TMP_SIZE		(1536 + STACK_TMP_OFFS)
#endif
#define STACK_THREAD_SIZE	8192

#ifdef CFG_CORE_SANITIZE_KADDRESS
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		2048
#endif

#endif /*ARM32*/

#ifdef ARM64
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS)
#define STACK_THREAD_SIZE	8192

#if TRACE_LEVEL > 0
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		1024
#endif
#endif /*ARM64*/

struct thread_ctx threads[CFG_NUM_THREADS];

struct thread_core_local thread_core_local[CFG_TEE_CORE_NB_CORE];

#ifdef CFG_WITH_STACK_CANARIES
#ifdef ARM32
#define STACK_CANARY_SIZE	(4 * sizeof(uint32_t))
#endif
#ifdef ARM64
#define STACK_CANARY_SIZE	(8 * sizeof(uint32_t))
#endif
#define START_CANARY_VALUE	0xdededede
#define END_CANARY_VALUE	0xabababab
#define GET_START_CANARY(name, stack_num) name[stack_num][0]
#define GET_END_CANARY(name, stack_num) \
	name[stack_num][sizeof(name[stack_num]) / sizeof(uint32_t) - 1]
#else
#define STACK_CANARY_SIZE	0
#endif

#define DECLARE_STACK(name, num_stacks, stack_size, linkage) \
linkage uint32_t name[num_stacks] \
		[ROUNDUP(stack_size + STACK_CANARY_SIZE, STACK_ALIGNMENT) / \
		sizeof(uint32_t)] \
		__attribute__((section(".nozi_stack"), \
			       aligned(STACK_ALIGNMENT)))

#define STACK_SIZE(stack) (sizeof(stack) - STACK_CANARY_SIZE / 2)

#define GET_STACK(stack) \
	((vaddr_t)(stack) + STACK_SIZE(stack))

DECLARE_STACK(stack_tmp, CFG_TEE_CORE_NB_CORE, STACK_TMP_SIZE, static);
DECLARE_STACK(stack_abt, CFG_TEE_CORE_NB_CORE, STACK_ABT_SIZE, static);
#ifndef CFG_WITH_PAGER
DECLARE_STACK(stack_thread, CFG_NUM_THREADS, STACK_THREAD_SIZE, static);
#endif

const void *stack_tmp_export = (uint8_t *)stack_tmp + sizeof(stack_tmp[0]) -
			       (STACK_TMP_OFFS + STACK_CANARY_SIZE / 2);
const uint32_t stack_tmp_stride = sizeof(stack_tmp[0]);

/*
 * These stack setup info are required by secondary boot cores before they
 * each locally enable the pager (the mmu). Hence kept in pager sections.
 */
KEEP_PAGER(stack_tmp_export);
KEEP_PAGER(stack_tmp_stride);

thread_smc_handler_t thread_std_smc_handler_ptr;
static thread_smc_handler_t thread_fast_smc_handler_ptr;
thread_nintr_handler_t thread_nintr_handler_ptr;
thread_pm_handler_t thread_cpu_on_handler_ptr;
thread_pm_handler_t thread_cpu_off_handler_ptr;
thread_pm_handler_t thread_cpu_suspend_handler_ptr;
thread_pm_handler_t thread_cpu_resume_handler_ptr;
thread_pm_handler_t thread_system_off_handler_ptr;
thread_pm_handler_t thread_system_reset_handler_ptr;


static unsigned int thread_global_lock = SPINLOCK_UNLOCK;
static bool thread_prealloc_rpc_cache;

static void init_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	size_t n;
#define INIT_CANARY(name)						\
	for (n = 0; n < ARRAY_SIZE(name); n++) {			\
		uint32_t *start_canary = &GET_START_CANARY(name, n);	\
		uint32_t *end_canary = &GET_END_CANARY(name, n);	\
									\
		*start_canary = START_CANARY_VALUE;			\
		*end_canary = END_CANARY_VALUE;				\
		DMSG("#Stack canaries for %s[%zu] with top at %p\n",	\
			#name, n, (void *)(end_canary - 1));		\
		DMSG("watch *%p\n", (void *)end_canary);		\
	}

	INIT_CANARY(stack_tmp);
	INIT_CANARY(stack_abt);
#ifndef CFG_WITH_PAGER
	INIT_CANARY(stack_thread);
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

#define CANARY_DIED(stack, loc, n) \
	do { \
		EMSG_RAW("Dead canary at %s of '%s[%zu]'", #loc, #stack, n); \
		panic(); \
	} while (0)

void thread_check_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	size_t n;

	for (n = 0; n < ARRAY_SIZE(stack_tmp); n++) {
		if (GET_START_CANARY(stack_tmp, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_tmp, start, n);
		if (GET_END_CANARY(stack_tmp, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_tmp, end, n);
	}

	for (n = 0; n < ARRAY_SIZE(stack_abt); n++) {
		if (GET_START_CANARY(stack_abt, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_abt, start, n);
		if (GET_END_CANARY(stack_abt, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_abt, end, n);

	}
#ifndef CFG_WITH_PAGER
	for (n = 0; n < ARRAY_SIZE(stack_thread); n++) {
		if (GET_START_CANARY(stack_thread, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_thread, start, n);
		if (GET_END_CANARY(stack_thread, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_thread, end, n);
	}
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

static void lock_global(void)
{
	cpu_spin_lock(&thread_global_lock);
}

static void unlock_global(void)
{
	cpu_spin_unlock(&thread_global_lock);
}

#ifdef ARM32
uint32_t thread_get_exceptions(void)
{
	uint32_t cpsr = read_cpsr();

	return (cpsr >> CPSR_F_SHIFT) & THREAD_EXCP_ALL;
}

void thread_set_exceptions(uint32_t exceptions)
{
	uint32_t cpsr = read_cpsr();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	cpsr &= ~(THREAD_EXCP_ALL << CPSR_F_SHIFT);
	cpsr |= ((exceptions & THREAD_EXCP_ALL) << CPSR_F_SHIFT);
	write_cpsr(cpsr);
}
#endif /*ARM32*/

#ifdef ARM64
uint32_t thread_get_exceptions(void)
{
	uint32_t daif = read_daif();

	return (daif >> DAIF_F_SHIFT) & THREAD_EXCP_ALL;
}

void thread_set_exceptions(uint32_t exceptions)
{
	uint32_t daif = read_daif();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	daif &= ~(THREAD_EXCP_ALL << DAIF_F_SHIFT);
	daif |= ((exceptions & THREAD_EXCP_ALL) << DAIF_F_SHIFT);
	write_daif(daif);
}
#endif /*ARM64*/

uint32_t thread_mask_exceptions(uint32_t exceptions)
{
	uint32_t state = thread_get_exceptions();

	thread_set_exceptions(state | (exceptions & THREAD_EXCP_ALL));
	return state;
}

void thread_unmask_exceptions(uint32_t state)
{
	thread_set_exceptions(state & THREAD_EXCP_ALL);
}


struct thread_core_local *thread_get_core_local(void)
{
	uint32_t cpu_id = get_core_pos();

	/*
	 * Foreign interrupts must be disabled before playing with core_local
	 * since we otherwise may be rescheduled to a different core in the
	 * middle of this function.
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	assert(cpu_id < CFG_TEE_CORE_NB_CORE);
	return &thread_core_local[cpu_id];
}

static void thread_lazy_save_ns_vfp(void)
{
#ifdef CFG_WITH_VFP
	struct thread_ctx *thr = threads + thread_get_id();

	thr->vfp_state.ns_saved = false;
#if defined(ARM64) && defined(CFG_WITH_ARM_TRUSTED_FW)
	/*
	 * ARM TF saves and restores CPACR_EL1, so we must assume NS world
	 * uses VFP and always preserve the register file when secure world
	 * is about to use it
	 */
	thr->vfp_state.ns.force_save = true;
#endif
	vfp_lazy_save_state_init(&thr->vfp_state.ns);
#endif /*CFG_WITH_VFP*/
}

static void thread_lazy_restore_ns_vfp(void)
{
#ifdef CFG_WITH_VFP
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(!thr->vfp_state.sec_lazy_saved && !thr->vfp_state.sec_saved);

	if (tuv && tuv->lazy_saved && !tuv->saved) {
		vfp_lazy_save_state_final(&tuv->vfp);
		tuv->saved = true;
	}

	vfp_lazy_restore_state(&thr->vfp_state.ns, thr->vfp_state.ns_saved);
	thr->vfp_state.ns_saved = false;
#endif /*CFG_WITH_VFP*/
}

#ifdef ARM32
static void init_regs(struct thread_ctx *thread,
		struct thread_smc_args *args)
{
	thread->regs.pc = (uint32_t)thread_std_smc_entry;

	/*
	 * Stdcalls starts in SVC mode with masked foreign interrupts, masked
	 * Asynchronous abort and unmasked native interrupts.
	 */
	thread->regs.cpsr = read_cpsr() & ARM32_CPSR_E;
	thread->regs.cpsr |= CPSR_MODE_SVC | CPSR_A |
			(THREAD_EXCP_FOREIGN_INTR << ARM32_CPSR_F_SHIFT);
	/* Enable thumb mode if it's a thumb instruction */
	if (thread->regs.pc & 1)
		thread->regs.cpsr |= CPSR_T;
	/* Reinitialize stack pointer */
	thread->regs.svc_sp = thread->stack_va_end;

	/*
	 * Copy arguments into context. This will make the
	 * arguments appear in r0-r7 when thread is started.
	 */
	thread->regs.r0 = args->a0;
	thread->regs.r1 = args->a1;
	thread->regs.r2 = args->a2;
	thread->regs.r3 = args->a3;
	thread->regs.r4 = args->a4;
	thread->regs.r5 = args->a5;
	thread->regs.r6 = args->a6;
	thread->regs.r7 = args->a7;
}
#endif /*ARM32*/

#ifdef ARM64
static void init_regs(struct thread_ctx *thread,
		struct thread_smc_args *args)
{
	thread->regs.pc = (uint64_t)thread_std_smc_entry;

	/*
	 * Stdcalls starts in SVC mode with masked foreign interrupts, masked
	 * Asynchronous abort and unmasked native interrupts.
	 */
	thread->regs.cpsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0,
				THREAD_EXCP_FOREIGN_INTR | DAIFBIT_ABT);
	/* Reinitialize stack pointer */
	thread->regs.sp = thread->stack_va_end;

	/*
	 * Copy arguments into context. This will make the
	 * arguments appear in x0-x7 when thread is started.
	 */
	thread->regs.x[0] = args->a0;
	thread->regs.x[1] = args->a1;
	thread->regs.x[2] = args->a2;
	thread->regs.x[3] = args->a3;
	thread->regs.x[4] = args->a4;
	thread->regs.x[5] = args->a5;
	thread->regs.x[6] = args->a6;
	thread->regs.x[7] = args->a7;

	/* Set up frame pointer as per the Aarch64 AAPCS */
	thread->regs.x[29] = 0;
}
#endif /*ARM64*/

void thread_init_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();
	size_t n;

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		TAILQ_INIT(&threads[n].mutexes);
		TAILQ_INIT(&threads[n].tsd.sess_stack);
		SLIST_INIT(&threads[n].tsd.pgt_cache);
	}

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		thread_core_local[n].curr_thread = -1;

	l->curr_thread = 0;
	threads[0].state = THREAD_STATE_ACTIVE;
}

void thread_clr_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread >= 0 && l->curr_thread < CFG_NUM_THREADS);
	assert(threads[l->curr_thread].state == THREAD_STATE_ACTIVE);
	assert(TAILQ_EMPTY(&threads[l->curr_thread].mutexes));
	threads[l->curr_thread].state = THREAD_STATE_FREE;
	l->curr_thread = -1;
}

static void thread_alloc_and_run(struct thread_smc_args *args)
{
	size_t n;
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == -1);

	lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state == THREAD_STATE_FREE) {
			threads[n].state = THREAD_STATE_ACTIVE;
			found_thread = true;
			break;
		}
	}

	unlock_global();

	if (!found_thread) {
		args->a0 = OPTEE_SMC_RETURN_ETHREAD_LIMIT;
		return;
	}

	l->curr_thread = n;

	threads[n].flags = 0;
	init_regs(threads + n, args);

	/* Save Hypervisor Client ID */
	threads[n].hyp_clnt_id = args->a7;

	thread_lazy_save_ns_vfp();
	thread_resume(&threads[n].regs);
}

#ifdef ARM32
static void copy_a0_to_a5(struct thread_ctx_regs *regs,
		struct thread_smc_args *args)
{
	/*
	 * Update returned values from RPC, values will appear in
	 * r0-r3 when thread is resumed.
	 */
	regs->r0 = args->a0;
	regs->r1 = args->a1;
	regs->r2 = args->a2;
	regs->r3 = args->a3;
	regs->r4 = args->a4;
	regs->r5 = args->a5;
}
#endif /*ARM32*/

#ifdef ARM64
static void copy_a0_to_a5(struct thread_ctx_regs *regs,
		struct thread_smc_args *args)
{
	/*
	 * Update returned values from RPC, values will appear in
	 * x0-x3 when thread is resumed.
	 */
	regs->x[0] = args->a0;
	regs->x[1] = args->a1;
	regs->x[2] = args->a2;
	regs->x[3] = args->a3;
	regs->x[4] = args->a4;
	regs->x[5] = args->a5;
}
#endif /*ARM64*/

#ifdef ARM32
static bool is_from_user(uint32_t cpsr)
{
	return (cpsr & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_USR;
}
#endif

#ifdef ARM64
static bool is_from_user(uint32_t cpsr)
{
	if (cpsr & (SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT))
		return true;
	if (((cpsr >> SPSR_64_MODE_EL_SHIFT) & SPSR_64_MODE_EL_MASK) ==
	     SPSR_64_MODE_EL0)
		return true;
	return false;
}
#endif

static bool is_user_mode(struct thread_ctx_regs *regs)
{
	return is_from_user((uint32_t)regs->cpsr);
}

static void thread_resume_from_rpc(struct thread_smc_args *args)
{
	size_t n = args->a3; /* thread id */
	struct thread_core_local *l = thread_get_core_local();
	uint32_t rv = 0;

	assert(l->curr_thread == -1);

	lock_global();

	if (n < CFG_NUM_THREADS &&
	    threads[n].state == THREAD_STATE_SUSPENDED &&
	    args->a7 == threads[n].hyp_clnt_id)
		threads[n].state = THREAD_STATE_ACTIVE;
	else
		rv = OPTEE_SMC_RETURN_ERESUME;

	unlock_global();

	if (rv) {
		args->a0 = rv;
		return;
	}

	l->curr_thread = n;

	if (is_user_mode(&threads[n].regs))
		tee_ta_update_session_utime_resume();

	if (threads[n].have_user_map)
		core_mmu_set_user_map(&threads[n].user_map);

	/*
	 * Return from RPC to request service of a foreign interrupt must not
	 * get parameters from non-secure world.
	 */
	if (threads[n].flags & THREAD_FLAGS_COPY_ARGS_ON_RETURN) {
		copy_a0_to_a5(&threads[n].regs, args);
		threads[n].flags &= ~THREAD_FLAGS_COPY_ARGS_ON_RETURN;
	}

	thread_lazy_save_ns_vfp();
	thread_resume(&threads[n].regs);
}

void thread_handle_fast_smc(struct thread_smc_args *args)
{
	thread_check_canaries();
	thread_fast_smc_handler_ptr(args);
	/* Fast handlers must not unmask any exceptions */
	assert(thread_get_exceptions() == THREAD_EXCP_ALL);
}

void thread_handle_std_smc(struct thread_smc_args *args)
{
	thread_check_canaries();

	if (args->a0 == OPTEE_SMC_CALL_RETURN_FROM_RPC)
		thread_resume_from_rpc(args);
	else
		thread_alloc_and_run(args);
}

/*
 * Helper routine for the assembly function thread_std_smc_entry()
 *
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak __thread_std_smc_entry(struct thread_smc_args *args)
{
	thread_std_smc_handler_ptr(args);

	if (args->a0 == OPTEE_SMC_RETURN_OK) {
		struct thread_ctx *thr = threads + thread_get_id();

		tee_fs_rpc_cache_clear(&thr->tsd);
		if (!thread_prealloc_rpc_cache) {
			thread_rpc_free_arg(thr->rpc_carg);
			mobj_free(thr->rpc_mobj);
			thr->rpc_carg = 0;
			thr->rpc_arg = 0;
			thr->rpc_mobj = NULL;
		}
	}
}

void *thread_get_tmp_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();

	return (void *)l->tmp_stack_va_end;
}

#ifdef ARM64
vaddr_t thread_get_saved_thread_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);
	return threads[ct].kern_sp;
}
#endif /*ARM64*/

vaddr_t thread_stack_start(void)
{
	struct thread_ctx *thr;
	int ct = thread_get_id_may_fail();

	if (ct == -1)
		return 0;

	thr = threads + ct;
	return thr->stack_va_end - STACK_THREAD_SIZE;
}

size_t thread_stack_size(void)
{
	return STACK_THREAD_SIZE;
}

bool thread_is_from_abort_mode(void)
{
	struct thread_core_local *l = thread_get_core_local();

	return (l->flags >> THREAD_CLF_SAVED_SHIFT) & THREAD_CLF_ABORT;
}

#ifdef ARM32
bool thread_is_in_normal_mode(void)
{
	return (read_cpsr() & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_SVC;
}
#endif

#ifdef ARM64
bool thread_is_in_normal_mode(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	bool ret;

	/* If any bit in l->flags is set we're handling some exception. */
	ret = !l->flags;
	thread_unmask_exceptions(exceptions);

	return ret;
}
#endif

void thread_state_free(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);
	assert(TAILQ_EMPTY(&threads[ct].mutexes));

	thread_lazy_restore_ns_vfp();
	tee_pager_release_phys(
		(void *)(threads[ct].stack_va_end - STACK_THREAD_SIZE),
		STACK_THREAD_SIZE);

	lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = -1;

	unlock_global();
}

#ifdef CFG_WITH_PAGER
static void release_unused_kernel_stack(struct thread_ctx *thr,
					uint32_t cpsr __maybe_unused)
{
#ifdef ARM64
	/*
	 * If we're from user mode then thr->regs.sp is the saved user
	 * stack pointer and thr->kern_sp holds the last kernel stack
	 * pointer. But if we're from kernel mode then thr->kern_sp isn't
	 * up to date so we need to read from thr->regs.sp instead.
	 */
	vaddr_t sp = is_from_user(cpsr) ?  thr->kern_sp : thr->regs.sp;
#else
	vaddr_t sp = thr->regs.svc_sp;
#endif
	vaddr_t base = thr->stack_va_end - STACK_THREAD_SIZE;
	size_t len = sp - base;

	tee_pager_release_phys((void *)base, len);
}
#else
static void release_unused_kernel_stack(struct thread_ctx *thr __unused,
					uint32_t cpsr __unused)
{
}
#endif

int thread_state_suspend(uint32_t flags, uint32_t cpsr, vaddr_t pc)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);

	thread_check_canaries();

	release_unused_kernel_stack(threads + ct, cpsr);

	if (is_from_user(cpsr)) {
		thread_user_save_vfp();
		tee_ta_update_session_utime_suspend();
		tee_ta_gprof_sample_pc(pc);
	}
	thread_lazy_restore_ns_vfp();

	lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].flags |= flags;
	threads[ct].regs.cpsr = cpsr;
	threads[ct].regs.pc = pc;
	threads[ct].state = THREAD_STATE_SUSPENDED;

	threads[ct].have_user_map = core_mmu_user_mapping_is_active();
	if (threads[ct].have_user_map) {
		core_mmu_get_user_map(&threads[ct].user_map);
		core_mmu_set_user_map(NULL);
	}

	l->curr_thread = -1;

	unlock_global();

	return ct;
}

#ifdef ARM32
static void set_tmp_stack(struct thread_core_local *l, vaddr_t sp)
{
	l->tmp_stack_va_end = sp;
	thread_set_irq_sp(sp);
	thread_set_fiq_sp(sp);
}

static void set_abt_stack(struct thread_core_local *l, vaddr_t sp)
{
	l->abt_stack_va_end = sp;
	thread_set_abt_sp((vaddr_t)l);
	thread_set_und_sp((vaddr_t)l);
}
#endif /*ARM32*/

#ifdef ARM64
static void set_tmp_stack(struct thread_core_local *l, vaddr_t sp)
{
	/*
	 * We're already using the tmp stack when this function is called
	 * so there's no need to assign it to any stack pointer. However,
	 * we'll need to restore it at different times so store it here.
	 */
	l->tmp_stack_va_end = sp;
}

static void set_abt_stack(struct thread_core_local *l, vaddr_t sp)
{
	l->abt_stack_va_end = sp;
}
#endif /*ARM64*/

bool thread_init_stack(uint32_t thread_id, vaddr_t sp)
{
	if (thread_id >= CFG_NUM_THREADS)
		return false;
	threads[thread_id].stack_va_end = sp;
	return true;
}

int thread_get_id_may_fail(void)
{
	/*
	 * thread_get_core_local() requires foreign interrupts to be disabled
	 */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	thread_unmask_exceptions(exceptions);
	return ct;
}

int thread_get_id(void)
{
	int ct = thread_get_id_may_fail();

	assert(ct >= 0 && ct < CFG_NUM_THREADS);
	return ct;
}

static void init_handlers(const struct thread_handlers *handlers)
{
	thread_std_smc_handler_ptr = handlers->std_smc;
	thread_fast_smc_handler_ptr = handlers->fast_smc;
	thread_nintr_handler_ptr = handlers->nintr;
	thread_cpu_on_handler_ptr = handlers->cpu_on;
	thread_cpu_off_handler_ptr = handlers->cpu_off;
	thread_cpu_suspend_handler_ptr = handlers->cpu_suspend;
	thread_cpu_resume_handler_ptr = handlers->cpu_resume;
	thread_system_off_handler_ptr = handlers->system_off;
	thread_system_reset_handler_ptr = handlers->system_reset;
}

#ifdef CFG_WITH_PAGER
static void init_thread_stacks(void)
{
	size_t n;

	/*
	 * Allocate virtual memory for thread stacks.
	 */
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		tee_mm_entry_t *mm;
		vaddr_t sp;

		/* Find vmem for thread stack and its protection gap */
		mm = tee_mm_alloc(&tee_mm_vcore,
				  SMALL_PAGE_SIZE + STACK_THREAD_SIZE);
		assert(mm);

		/* Claim eventual physical page */
		tee_pager_add_pages(tee_mm_get_smem(mm), tee_mm_get_size(mm),
				    true);

		/* Add the area to the pager */
		tee_pager_add_core_area(tee_mm_get_smem(mm) + SMALL_PAGE_SIZE,
					tee_mm_get_bytes(mm) - SMALL_PAGE_SIZE,
					TEE_MATTR_PRW | TEE_MATTR_LOCKED,
					NULL, NULL);

		/* init effective stack */
		sp = tee_mm_get_smem(mm) + tee_mm_get_bytes(mm);
		asan_tag_access((void *)tee_mm_get_smem(mm), (void *)sp);
		if (!thread_init_stack(n, sp))
			panic("init stack failed");
	}
}
#else
static void init_thread_stacks(void)
{
	size_t n;

	/* Assign the thread stacks */
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (!thread_init_stack(n, GET_STACK(stack_thread[n])))
			panic("thread_init_stack failed");
	}
}
#endif /*CFG_WITH_PAGER*/

void thread_init_primary(const struct thread_handlers *handlers)
{
	init_handlers(handlers);

	/* Initialize canaries around the stacks */
	init_canaries();

	init_thread_stacks();
	pgt_init();
}

static void init_sec_mon(size_t pos __maybe_unused)
{
#if !defined(CFG_WITH_ARM_TRUSTED_FW)
	/* Initialize secure monitor */
	sm_init(GET_STACK(stack_tmp[pos]));
#endif
}

void thread_init_per_cpu(void)
{
	size_t pos = get_core_pos();
	struct thread_core_local *l = thread_get_core_local();

	init_sec_mon(pos);

	set_tmp_stack(l, GET_STACK(stack_tmp[pos]) - STACK_TMP_OFFS);
	set_abt_stack(l, GET_STACK(stack_abt[pos]));

	thread_init_vbar();
}

struct thread_specific_data *thread_get_tsd(void)
{
	return &threads[thread_get_id()].tsd;
}

struct thread_ctx_regs *thread_get_ctx_regs(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread != -1);
	return &threads[l->curr_thread].regs;
}

void thread_set_foreign_intr(bool enable)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != -1);

	if (enable) {
		threads[l->curr_thread].flags |=
					THREAD_FLAGS_FOREIGN_INTR_ENABLE;
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
	} else {
		/*
		 * No need to disable foreign interrupts here since they're
		 * already disabled above.
		 */
		threads[l->curr_thread].flags &=
					~THREAD_FLAGS_FOREIGN_INTR_ENABLE;
	}
}

void thread_restore_foreign_intr(void)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != -1);

	if (threads[l->curr_thread].flags & THREAD_FLAGS_FOREIGN_INTR_ENABLE)
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
}

#ifdef CFG_WITH_VFP
uint32_t thread_kernel_enable_vfp(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(!vfp_is_enabled());

	if (!thr->vfp_state.ns_saved) {
		vfp_lazy_save_state_final(&thr->vfp_state.ns);
		thr->vfp_state.ns_saved = true;
	} else if (thr->vfp_state.sec_lazy_saved &&
		   !thr->vfp_state.sec_saved) {
		/*
		 * This happens when we're handling an abort while the
		 * thread was using the VFP state.
		 */
		vfp_lazy_save_state_final(&thr->vfp_state.sec);
		thr->vfp_state.sec_saved = true;
	} else if (tuv && tuv->lazy_saved && !tuv->saved) {
		/*
		 * This can happen either during syscall or abort
		 * processing (while processing a syscall).
		 */
		vfp_lazy_save_state_final(&tuv->vfp);
		tuv->saved = true;
	}

	vfp_enable();
	return exceptions;
}

void thread_kernel_disable_vfp(uint32_t state)
{
	uint32_t exceptions;

	assert(vfp_is_enabled());

	vfp_disable();
	exceptions = thread_get_exceptions();
	assert(exceptions & THREAD_EXCP_FOREIGN_INTR);
	exceptions &= ~THREAD_EXCP_FOREIGN_INTR;
	exceptions |= state & THREAD_EXCP_FOREIGN_INTR;
	thread_set_exceptions(exceptions);
}

void thread_kernel_save_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	if (vfp_is_enabled()) {
		vfp_lazy_save_state_init(&thr->vfp_state.sec);
		thr->vfp_state.sec_lazy_saved = true;
	}
}

void thread_kernel_restore_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	assert(!vfp_is_enabled());
	if (thr->vfp_state.sec_lazy_saved) {
		vfp_lazy_restore_state(&thr->vfp_state.sec,
				       thr->vfp_state.sec_saved);
		thr->vfp_state.sec_saved = false;
		thr->vfp_state.sec_lazy_saved = false;
	}
}

void thread_user_enable_vfp(struct thread_user_vfp_state *uvfp)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	assert(!vfp_is_enabled());

	if (!thr->vfp_state.ns_saved) {
		vfp_lazy_save_state_final(&thr->vfp_state.ns);
		thr->vfp_state.ns_saved = true;
	} else if (tuv && uvfp != tuv) {
		if (tuv->lazy_saved && !tuv->saved) {
			vfp_lazy_save_state_final(&tuv->vfp);
			tuv->saved = true;
		}
	}

	if (uvfp->lazy_saved)
		vfp_lazy_restore_state(&uvfp->vfp, uvfp->saved);
	uvfp->lazy_saved = false;
	uvfp->saved = false;

	thr->vfp_state.uvfp = uvfp;
	vfp_enable();
}

void thread_user_save_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	if (!vfp_is_enabled())
		return;

	assert(tuv && !tuv->lazy_saved && !tuv->saved);
	vfp_lazy_save_state_init(&tuv->vfp);
	tuv->lazy_saved = true;
}

void thread_user_clear_vfp(struct thread_user_vfp_state *uvfp)
{
	struct thread_ctx *thr = threads + thread_get_id();

	if (uvfp == thr->vfp_state.uvfp)
		thr->vfp_state.uvfp = NULL;
	uvfp->lazy_saved = false;
	uvfp->saved = false;
}
#endif /*CFG_WITH_VFP*/

#ifdef ARM32
static bool get_spsr(bool is_32bit, unsigned long entry_func, uint32_t *spsr)
{
	uint32_t s;

	if (!is_32bit)
		return false;

	s = read_spsr();
	s &= ~(CPSR_MODE_MASK | CPSR_T | CPSR_IT_MASK1 | CPSR_IT_MASK2);
	s |= CPSR_MODE_USR;
	if (entry_func & 1)
		s |= CPSR_T;
	*spsr = s;
	return true;
}
#endif

#ifdef ARM64
static bool get_spsr(bool is_32bit, unsigned long entry_func, uint32_t *spsr)
{
	uint32_t s;

	if (is_32bit) {
		s = read_daif() & (SPSR_32_AIF_MASK << SPSR_32_AIF_SHIFT);
		s |= SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT;
		s |= (entry_func & SPSR_32_T_MASK) << SPSR_32_T_SHIFT;
	} else {
		s = read_daif() & (SPSR_64_DAIF_MASK << SPSR_64_DAIF_SHIFT);
	}

	*spsr = s;
	return true;
}
#endif

uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3, unsigned long user_sp,
		unsigned long entry_func, bool is_32bit,
		uint32_t *exit_status0, uint32_t *exit_status1)
{
	uint32_t spsr;

	tee_ta_update_session_utime_resume();

	if (!get_spsr(is_32bit, entry_func, &spsr)) {
		*exit_status0 = 1; /* panic */
		*exit_status1 = 0xbadbadba;
		return 0;
	}
	return __thread_enter_user_mode(a0, a1, a2, a3, user_sp, entry_func,
					spsr, exit_status0, exit_status1);
}

void thread_add_mutex(struct mutex *m)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1 && threads[ct].state == THREAD_STATE_ACTIVE);
	assert(m->owner_id == MUTEX_OWNER_ID_NONE);
	m->owner_id = ct;
	TAILQ_INSERT_TAIL(&threads[ct].mutexes, m, link);
}

void thread_rem_mutex(struct mutex *m)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1 && threads[ct].state == THREAD_STATE_ACTIVE);
	assert(m->owner_id == ct);
	m->owner_id = MUTEX_OWNER_ID_NONE;
	TAILQ_REMOVE(&threads[ct].mutexes, m, link);
}

bool thread_disable_prealloc_rpc_cache(uint64_t *cookie)
{
	bool rv;
	size_t n;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state != THREAD_STATE_FREE) {
			rv = false;
			goto out;
		}
	}

	rv = true;
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].rpc_arg) {
			mobj_free(threads[n].rpc_mobj);
			*cookie = threads[n].rpc_carg;
			threads[n].rpc_carg = 0;
			threads[n].rpc_arg = NULL;
			goto out;
		}
	}

	*cookie = 0;
	thread_prealloc_rpc_cache = false;
out:
	unlock_global();
	thread_unmask_exceptions(exceptions);
	return rv;
}

bool thread_enable_prealloc_rpc_cache(void)
{
	bool rv;
	size_t n;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state != THREAD_STATE_FREE) {
			rv = false;
			goto out;
		}
	}

	rv = true;
	thread_prealloc_rpc_cache = true;
out:
	unlock_global();
	thread_unmask_exceptions(exceptions);
	return rv;
}

void thread_rpc_free_arg(uint64_t cookie)
{
	if (cookie) {
		uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
			OPTEE_SMC_RETURN_RPC_FREE
		};

		reg_pair_from_64(cookie, rpc_args + 1, rpc_args + 2);
		thread_rpc(rpc_args);
	}
}

struct mobj *thread_rpc_alloc_arg(size_t size, uint64_t *cookie)
{
	paddr_t pa;
	uint64_t co;
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
		OPTEE_SMC_RETURN_RPC_ALLOC, size
	};
	struct mobj *mobj = NULL;

	thread_rpc(rpc_args);

	pa = reg_pair_to_64(rpc_args[1], rpc_args[2]);
	co = reg_pair_to_64(rpc_args[4], rpc_args[5]);

	if (!ALIGNMENT_IS_OK(pa, struct optee_msg_arg))
		goto err;

	/* Check if this region is in static shared space */
	if (core_pbuf_is(CORE_MEM_NSEC_SHM, pa, size))
		mobj = mobj_shm_alloc(pa, size);
	else if ((!(pa & SMALL_PAGE_MASK)) && size <= SMALL_PAGE_SIZE)
		mobj = mobj_mapped_shm_alloc(&pa, 1, 0, co);

	if (!mobj)
		goto err;

	*cookie = co;
	return mobj;
err:
	thread_rpc_free_arg(co);
	mobj_free(mobj);
	*cookie = 0;
	return NULL;
}

static bool get_rpc_arg(uint32_t cmd, size_t num_params,
			struct optee_msg_arg **arg_ret, uint64_t *carg_ret)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct optee_msg_arg *arg = thr->rpc_arg;
	struct mobj *mobj;
	size_t sz = OPTEE_MSG_GET_ARG_SIZE(THREAD_RPC_MAX_NUM_PARAMS);
	uint64_t c;

	if (num_params > THREAD_RPC_MAX_NUM_PARAMS)
		return false;

	if (!arg) {
		mobj = thread_rpc_alloc_arg(sz, &c);
		if (!mobj)
			return false;

		arg = mobj_get_va(mobj, 0);
		if (!arg)
			goto bad;

		thr->rpc_arg = arg;
		thr->rpc_carg = c;
		thr->rpc_mobj = mobj;
	}

	memset(arg, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	arg->cmd = cmd;
	arg->num_params = num_params;
	arg->ret = TEE_ERROR_GENERIC; /* in case value isn't updated */

	*arg_ret = arg;
	*carg_ret = thr->rpc_carg;
	return true;

bad:
	thread_rpc_free_arg(c);
	return false;
}

uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
			struct optee_msg_param *params)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	struct optee_msg_arg *arg;
	uint64_t carg;
	size_t n;

	/*
	 * Break recursion in case plat_prng_add_jitter_entropy_norpc()
	 * sleeps on a mutex or unlocks a mutex with a sleeper (contended
	 * mutex).
	 */
	if (cmd != OPTEE_MSG_RPC_CMD_WAIT_QUEUE)
		plat_prng_add_jitter_entropy_norpc();

	if (!get_rpc_arg(cmd, num_params, &arg, &carg))
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(arg->params, params, sizeof(*params) * num_params);

	reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
	thread_rpc(rpc_args);
	for (n = 0; n < num_params; n++) {
		switch (params[n].attr & OPTEE_MSG_ATTR_TYPE_MASK) {
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			params[n] = arg->params[n];
			break;
		default:
			break;
		}
	}
	return arg->ret;
}

/**
 * Free physical memory previously allocated with thread_rpc_alloc()
 *
 * @cookie:	cookie received when allocating the buffer
 * @bt:		must be the same as supplied when allocating
 * @mobj:	mobj that describes allocated buffer
 *
 * This function also frees corresponding mobj.
 */
static void thread_rpc_free(unsigned int bt, uint64_t cookie, struct mobj *mobj)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	struct optee_msg_arg *arg;
	uint64_t carg;

	if (!get_rpc_arg(OPTEE_MSG_RPC_CMD_SHM_FREE, 1, &arg, &carg))
		return;

	arg->params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	arg->params[0].u.value.a = bt;
	arg->params[0].u.value.b = cookie;
	arg->params[0].u.value.c = 0;

	mobj_free(mobj);

	reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
	thread_rpc(rpc_args);
}

/**
 * Allocates shared memory buffer via RPC
 *
 * @size:	size in bytes of shared memory buffer
 * @align:	required alignment of buffer
 * @bt:		buffer type OPTEE_MSG_RPC_SHM_TYPE_*
 * @payload:	returned physical pointer to buffer, 0 if allocation
 *		failed.
 * @cookie:	returned cookie used when freeing the buffer
 */
static struct mobj *thread_rpc_alloc(size_t size, size_t align, unsigned int bt,
				     uint64_t *cookie)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = { OPTEE_SMC_RETURN_RPC_CMD };
	struct optee_msg_arg *arg;
	uint64_t carg;
	struct mobj *mobj = NULL;

	if (!get_rpc_arg(OPTEE_MSG_RPC_CMD_SHM_ALLOC, 1, &arg, &carg))
		goto fail;

	arg->params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	arg->params[0].u.value.a = bt;
	arg->params[0].u.value.b = size;
	arg->params[0].u.value.c = align;

	reg_pair_from_64(carg, rpc_args + 1, rpc_args + 2);
	thread_rpc(rpc_args);

	if (arg->ret != TEE_SUCCESS)
		goto fail;

	if (arg->num_params != 1)
		goto fail;

	if (arg->params[0].attr == OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT) {
		*cookie = arg->params[0].u.tmem.shm_ref;
		mobj = mobj_shm_alloc(arg->params[0].u.tmem.buf_ptr,
				      arg->params[0].u.tmem.size);
	} else if (arg->params[0].attr == (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
					   OPTEE_MSG_ATTR_NONCONTIG)) {
		*cookie = arg->params[0].u.tmem.shm_ref;
		mobj = msg_param_mobj_from_noncontig(
			arg->params[0].u.tmem.buf_ptr,
			arg->params[0].u.tmem.size,
			*cookie,
			true);
	} else
		goto fail;

	if (!mobj)
		goto free_first;

	assert(mobj_is_nonsec(mobj));
	return mobj;

free_first:
	thread_rpc_free(bt, *cookie, mobj);
fail:
	*cookie = 0;
	return NULL;
}

struct mobj *thread_rpc_alloc_payload(size_t size, uint64_t *cookie)
{
	return thread_rpc_alloc(size, 8, OPTEE_MSG_RPC_SHM_TYPE_APPL, cookie);
}

void thread_rpc_free_payload(uint64_t cookie, struct mobj *mobj)
{
	thread_rpc_free(OPTEE_MSG_RPC_SHM_TYPE_APPL, cookie, mobj);
}
