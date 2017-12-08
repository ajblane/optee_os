
/*============================================================================

This C source file is part of the SoftFloat IEEE Floating-Point Arithmetic
Package, Release 3a, by John R. Hauser.

Copyright 2011, 2012, 2013, 2014 The Regents of the University of California.
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions, and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions, and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the University nor the names of its contributors may
    be used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS", AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE
DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=============================================================================*/

#include <stdbool.h>
#include <stdint.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

uint_fast32_t
 extF80_to_ui32( extFloat80_t a, uint_fast8_t roundingMode, bool exact )
{
    union { struct extFloat80M s; extFloat80_t f; } uA;
    uint_fast16_t uiA64;
    bool sign;
    int_fast32_t exp;
    uint_fast64_t sig;
    int_fast32_t shiftCount;

    uA.f = a;
    uiA64 = uA.s.signExp;
    sign = signExtF80UI64( uiA64 );
    exp  = expExtF80UI64( uiA64 );
    sig = uA.s.signif;
    shiftCount = 0x4037 - exp;
    if ( shiftCount <= 0 ) shiftCount = 1;
    sig = softfloat_shiftRightJam64( sig, shiftCount );
    return softfloat_roundPackToUI32( sign, sig, roundingMode, exact );

}

