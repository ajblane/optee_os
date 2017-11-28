/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <atomic.h>
#include <kernel/refcount.h>

bool refcount_inc(struct refcount *r)
{
	unsigned int nval;
	unsigned int oval = atomic_load_uint(&r->val);

	while (true) {
		nval = oval + 1;

		/* r->val is 0, we can't do anything more. */
		if (!oval)
			return false;

		/*
		 * Note that atomic_cas_uint() updates oval to the current
		 * r->val read, regardless of return value.
		 */
		if (atomic_cas_uint(&r->val, &oval, nval))
			return true;
	}
}

bool refcount_dec(struct refcount *r)
{
	unsigned int nval;
	unsigned int oval = atomic_load_uint(&r->val);

	while (true) {
		assert(oval);
		nval = oval - 1;

		/*
		 * Note that atomic_cas_uint() updates oval to the current
		 * r->val read, regardless of return value.
		 */
		if (atomic_cas_uint(&r->val, &oval, nval)) {
			/*
			 * Value has been updated, if value was set to 0
			 * return true to indicate that.
			 */
			return !nval;
		}
	}
}
