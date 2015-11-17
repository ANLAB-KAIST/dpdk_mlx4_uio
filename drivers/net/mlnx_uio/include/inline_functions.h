/*
 * inline_functions.h
 *
 *  Created on: Jun 24, 2015
 *      Author: leeopop
 */

#ifndef DRIVERS_NET_MLNX_UIO_INCLUDE_INLINE_FUNCTIONS_H_
#define DRIVERS_NET_MLNX_UIO_INCLUDE_INLINE_FUNCTIONS_H_

#include <pthread.h>

struct completion
{
	int done;
	pthread_cond_t wait;
	pthread_mutex_t lock;
};

#define INLINE_MACRO static inline __attribute__((always_inline))

INLINE_MACRO bool time_after(uint64_t a, uint64_t b)
{
	return a > b;
}

INLINE_MACRO bool time_before(uint64_t a, uint64_t b)
{
	return a < b;
}

INLINE_MACRO bool time_after_eq(uint64_t a, uint64_t b)
{
	return a >= b;
}

INLINE_MACRO bool time_before_eq(uint64_t a, uint64_t b)
{
	return a <= b;
}

/*	$OpenBSD: strlcpy.c,v 1.8 /06/17 21:56:24 millert Exp $	*/

/*
 * Copyright (c)  Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
INLINE_MACRO size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

/**
 * div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
 *
 * This is commonly provided by 32bit archs to provide an optimized 64bit
 * divide.
 */
INLINE_MACRO u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div_s64_rem - signed 64bit divide with 32bit divisor with remainder
 */
INLINE_MACRO s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}


INLINE_MACRO u64 div_u64(u64 dividend, u32 divisor)
{
	u32 remainder;
	return div_u64_rem(dividend, divisor, &remainder);
}

INLINE_MACRO s64 div_s64(s64 dividend, s32 divisor)
{
	s32 remainder;
	return div_s64_rem(dividend, divisor, &remainder);
}

INLINE_MACRO u8 read8(const volatile void* addr)
{
	return *((const volatile u8*)addr);
}

INLINE_MACRO void write8(u8 val, volatile void* addr)
{
	(*((volatile u8*)addr)) = val;
}

INLINE_MACRO u16 read16(const volatile void* addr)
{
	return *((const volatile u16*)addr);
}

INLINE_MACRO void write16(u16 val, volatile void* addr)
{
	(*((volatile u16*)addr)) = val;
}

INLINE_MACRO u32 read32(const volatile void* addr)
{
	return *((const volatile u32*)addr);
}

INLINE_MACRO void write32(u32 val, volatile void* addr)
{
	(*((volatile u32*)addr)) = val;
}

INLINE_MACRO u64 read64(const volatile void* addr)
{
	return *((const volatile u64*)addr);
}

INLINE_MACRO void write64(u64 val, volatile void* addr)
{
	(*((volatile u64*)addr)) = val;
}

INLINE_MACRO void sema_init(semaphore_t* sema, int val)
{
	mutex_init(&sema->lock);
	sema->count = val;
}

INLINE_MACRO void down(semaphore_t* sema)
{
	while(1)
	{
		mutex_lock(&sema->lock);
		if(sema->count > 0)
		{
			sema->count--;
			mutex_unlock(&sema->lock);
			break;
		}
		mutex_unlock(&sema->lock);
		cond_resched();
	}
}
INLINE_MACRO void up(semaphore_t* sema)
{
	mutex_lock(&sema->lock);
	sema->count++;
	mutex_unlock(&sema->lock);
}

INLINE_MACRO void init_completion(struct completion *x)
{
	x->done = 0;
	pthread_cond_init(&x->wait, NULL);
	pthread_mutex_init(&x->lock, NULL);
}

INLINE_MACRO void reinit_completion(struct completion *x)
{
	pthread_mutex_lock(&x->lock);
	x->done = 0;
	pthread_mutex_unlock(&x->lock);
}

INLINE_MACRO void wait_for_completion(struct completion *x)
{
	pthread_mutex_lock(&x->lock);
	while(x->done == 0)
		pthread_cond_wait(&x->wait, &x->lock);
	x->done--;
	pthread_mutex_unlock(&x->lock);
}
INLINE_MACRO void wait_for_completion_io(struct completion *x)
{
	wait_for_completion(x);
}
INLINE_MACRO int wait_for_completion_interruptible(struct completion *x)
{
	wait_for_completion(x);
	return 0;
}
INLINE_MACRO int wait_for_completion_killable(struct completion *x)
{
	wait_for_completion(x);
	return 0;
}
INLINE_MACRO unsigned long wait_for_completion_timeout(struct completion *x,
		unsigned long timeout)
{
	struct timespec time, endtime;
	int timeover = 0;
	unsigned long msec = jiffies_to_msec(timeout);
	unsigned long nsec = msec * NSEC_PER_MSEC;
	//gettimeofday(&time, NULL);
	clock_gettime(CLOCK_REALTIME_COARSE, &time);
	time.tv_nsec += nsec%NSEC_PER_SEC;
	time.tv_sec += nsec/NSEC_PER_SEC;
	time.tv_sec += time.tv_nsec/NSEC_PER_SEC;
	time.tv_nsec = time.tv_nsec%NSEC_PER_SEC;
	pthread_mutex_lock(&x->lock);
	while(!x->done && timeover == 0)
		timeover = pthread_cond_timedwait(&x->wait, &x->lock, &time);

	if(timeover == 0)
	{
		clock_gettime(CLOCK_REALTIME_COARSE, &endtime);
		//gettimeofday(&time, NULL);
		unsigned long remaining = MAX(1, (time.tv_sec - endtime.tv_sec)*NSEC_PER_SEC + time.tv_nsec - endtime.tv_nsec);
		x->done--;

		pthread_mutex_unlock(&x->lock);

		return remaining;
	}
	else
	{
		pthread_mutex_unlock(&x->lock);
		return 0;
	}
}
INLINE_MACRO unsigned long wait_for_completion_io_timeout(struct completion *x,
		unsigned long timeout)
{
	return wait_for_completion_timeout(x,timeout);
}
INLINE_MACRO unsigned long wait_for_completion_interruptible_timeout(
		struct completion *x, unsigned long timeout)
{
	return wait_for_completion_timeout(x,timeout);
}
INLINE_MACRO unsigned long wait_for_completion_killable_timeout(
		struct completion *x, unsigned long timeout)
{
	return wait_for_completion_timeout(x,timeout);
}
INLINE_MACRO bool try_wait_for_completion(struct completion *x)
{
	unsigned long ret = wait_for_completion_timeout(x, 1);
	return RTE_MIN(1UL, ret);
}
INLINE_MACRO bool completion_done(struct completion *x)
{
	bool ret;
	pthread_mutex_lock(&x->lock);
	ret = x->done;
	pthread_mutex_unlock(&x->lock);
	return ret;
}

INLINE_MACRO void complete(struct completion *x)
{
	pthread_mutex_lock(&x->lock);
	x->done++;
	pthread_cond_signal(&x->wait);
	pthread_mutex_unlock(&x->lock);
}
INLINE_MACRO void complete_all(struct completion *x)
{
	pthread_mutex_lock(&x->lock);
	x->done = INT_MAX;
	pthread_cond_broadcast(&x->wait);
	pthread_mutex_unlock(&x->lock);
}

#endif /* DRIVERS_NET_MLNX_UIO_INCLUDE_INLINE_FUNCTIONS_H_ */
