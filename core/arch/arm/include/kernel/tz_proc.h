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

#ifndef TZ_PROC_H
#define TZ_PROC_H

#define SPINLOCK_LOCK       1
#define SPINLOCK_UNLOCK     0

#ifndef ASM
#include <assert.h>
#include <kernel/thread.h>

void __cpu_spin_lock(unsigned int *lock);
unsigned int __cpu_spin_trylock(unsigned int *lock);
void __cpu_spin_unlock(unsigned int *lock);

static inline void cpu_spin_lock(unsigned int *lock)
{
	assert(thread_irq_disabled());
	__cpu_spin_lock(lock);
}

static inline unsigned int cpu_spin_trylock(unsigned int *lock)
{
	assert(thread_irq_disabled());
        return __cpu_spin_trylock(lock);
}

static inline void cpu_spin_unlock(unsigned int *lock)
{
	assert(thread_irq_disabled());
        __cpu_spin_unlock(lock);
}

void cpu_mmu_enable(void);
void cpu_mmu_enable_icache(void);
void cpu_mmu_enable_dcache(void);
#endif /*ASM*/

#endif
