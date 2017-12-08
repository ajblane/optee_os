/*-
 * Copyright (c) 2015 Linaro Limited
 * Copyright (c) 2015 The FreeBSD Foundation
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Semihalf under
 * the sponsorship of the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <arm.h>
#include <kernel/unwind.h>
#include <kernel/thread.h>
#include <string.h>
#include <trace.h>

bool unwind_stack_arm64(struct unwind_state_arm64 *frame, uaddr_t stack,
		      size_t stack_size)
{
	uint64_t fp;

	fp = frame->fp;
	if (fp < stack || fp >= stack + stack_size)
		return false;

	frame->sp = fp + 0x10;
	/* FP to previous frame (X29) */
	frame->fp = *(uint64_t *)(fp);
	/* LR (X30) */
	frame->pc = *(uint64_t *)(fp + 8) - 4;

	return true;
}

#if defined(CFG_UNWIND) && (TRACE_LEVEL > 0)

void print_stack_arm64(int level, struct unwind_state_arm64 *state,
		       uaddr_t stack, size_t stack_size)
{
	trace_printf_helper_raw(level, true, "Call stack:");
	do {
		trace_printf_helper_raw(level, true, " 0x%016" PRIx64,
					state->pc);
	} while (stack && unwind_stack_arm64(state, stack, stack_size));
}

void print_kernel_stack(int level)
{
	struct unwind_state_arm64 state;
	uaddr_t stack = thread_stack_start();
	size_t stack_size = thread_stack_size();

	memset(&state, 0, sizeof(state));
	state.pc = read_pc();
	state.fp = read_fp();

	print_stack_arm64(level, &state, stack, stack_size);
}

#endif
