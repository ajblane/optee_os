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

#ifndef KERNEL_PANIC_H
#define KERNEL_PANIC_H

#include <compiler.h>

/*
 * Suppress GCC warning on expansion of the panic() macro with no argument:
 *  'ISO C99 requires at least one argument for the "..." in a variadic macro'
 * Occurs when '-pedantic' is combined with '-std=gnu99'.
 * Suppression applies only to this file and the expansion of macros defined in
 * this file.
 */
#pragma GCC system_header

/*
 * panic() macro must expand itself __FILE__ and its friends.
 */
#define _panic0() __do_panic(__FILE__, __LINE__, __func__, (void *)0)
#define _panic1(s) __do_panic(__FILE__, __LINE__, __func__, s)
#define _panic_fn(_0, _1, name, ...) name
#define panic(...) _panic_fn(_0, ##__VA_ARGS__, _panic1, _panic0)(__VA_ARGS__)

void __do_panic(const char *file, const int line, const char *func,
		const char *msg) __noreturn;

#endif /*KERNEL_PANIC_H*/
