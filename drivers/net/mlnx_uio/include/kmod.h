/*
 * kmod.h
 *
 *  Created on: Jun 24, 2015
 *      Author: leeopop
 */

#ifndef DRIVERS_NET_MLNX_UIO_INCLUDE_KMOD_H_
#define DRIVERS_NET_MLNX_UIO_INCLUDE_KMOD_H_

#define KMOD_MODIFIED
#undef KMOD_DISABLED
#undef KMOD_REMOVED

#define CONFIG_MLX4_DEBUG

#include "autoconf.h"
#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_persistent.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_pci.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_eal.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include <errno.h>
#define ERESTARTSYS     512
#define ERESTARTNOINTR  513
#define ERESTARTNOHAND  514     /* restart if no handler.. */
#define ENOIOCTLCMD     515     /* No ioctl command */
#define ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */
#define EPROBE_DEFER    517     /* Driver requests probe retry */
#define EOPENSTALE      518     /* open found a stale dentry */

/* Defined for the NFSv3 protocol */
#define EBADHANDLE      521     /* Illegal NFS file handle */
#define ENOTSYNC        522     /* Update synchronization mismatch */
#define EBADCOOKIE      523     /* Cookie is stale */
#define ENOTSUPP        524     /* Operation is not supported */
#define ETOOSMALL       525     /* Buffer or request is too small */
#define ESERVERFAULT    526     /* An untranslatable error occurred */
#define EBADTYPE        527     /* Type not supported by server */
#define EJUKEBOX        528     /* Request initiated, but will not complete before timeout */
#define EIOCBQUEUED     529     /* iocb queued, will get completion event */

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <asm/bitsperlong.h>
#include <string.h>
#include <strings.h>
#include <memory.h>
#include <assert.h>

//linux include
#include <linux/if_link.h>
#include <sys/sysinfo.h>
#include <sys/pci.h>

#define __USE_MISC
#include <netinet/in.h>

#define BITS_PER_LONG __BITS_PER_LONG

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint64_t dma_addr_t;
#if 0

typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;
typedef s8 __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;


typedef uint64_t __be64;
typedef uint64_t __le64;
typedef uint32_t __be32;
typedef uint32_t __le32;
typedef uint16_t __be16;
typedef uint16_t __le16;
#endif

#define cpu_to_le16(X) rte_cpu_to_le_16(X)
#define cpu_to_le32(X) rte_cpu_to_le_32(X)
#define cpu_to_le64(X) rte_cpu_to_le_64(X)
#define cpu_to_be16(X) rte_cpu_to_be_16(X)
#define cpu_to_be32(X) rte_cpu_to_be_32(X)
#define cpu_to_be64(X) rte_cpu_to_be_64(X)

#define be16_to_cpu(X) rte_be_to_cpu_16(X)
#define be32_to_cpu(X) rte_be_to_cpu_32(X)
#define be64_to_cpu(X) rte_be_to_cpu_64(X)
#define le16_to_cpu(X) rte_le_to_cpu_16(X)
#define le32_to_cpu(X) rte_le_to_cpu_32(X)
#define le64_to_cpu(X) rte_le_to_cpu_64(X)

#define be64_to_cpup(X) be64_to_cpu(*((__be64*)(X)))
#define be32_to_cpup(X) be32_to_cpu(*((__be32*)(X)))
#define be16_to_cpup(X) be16_to_cpu(*((__be16*)(X)))

#define le64_to_cpup(X) le64_to_cpu(*((__le64*)(X)))
#define le32_to_cpup(X) le32_to_cpu(*((__le32*)(X)))
#define le16_to_cpup(X) le16_to_cpu(*((__le16*)(X)))

#if 0
#define be16_to_cpup(X) __be16_to_cpup(X)
#define be32_to_cpup(X) __be32_to_cpup(X)
#define be64_to_cpup(X) __be64_to_cpup(X)
#define be16_to_cpu(X) __be16_to_cpu(X)
#define be32_to_cpu(X) __be32_to_cpu(X)
#define be64_to_cpu(X) __be64_to_cpu(X)
#define le16_to_cpu(X) __le16_to_cpu(X)
#define le32_to_cpu(X) __le32_to_cpu(X)
#define le64_to_cpu(X) __le64_to_cpu(X)
#define le16_to_cpus(X) __le16_to_cpus(X)
#define le32_to_cpus(X) __le32_to_cpus(X)
#define cpu_to_be16(X) __cpu_to_be16(X)
#define cpu_to_be32(X) __cpu_to_be32(X)
#define cpu_to_be64(X) __cpu_to_be64(X)
#define cpu_to_le16(X) __cpu_to_le16(X)
#define cpu_to_le32(X) __cpu_to_le32(X)
#define cpu_to_le64(X) __cpu_to_le64(X)
#define cpu_to_le16s(X) __cpu_to_le16s(X)
#endif

#define swab16(X) rte_bswap16(X)
#define swab32(X) rte_bswap32(X)
#define swab64(X) rte_bswap64(X)

typedef unsigned gfp_t;
typedef unsigned fmode_t;
typedef unsigned oom_flags_t;

static inline int WARN_ON_ONCE(int val) { if(val != 0) printf("WARN_ON_ONCE\n"); return val; }
static inline int WARN_ON(int val) { if(val != 0) printf("WARN_ON\n"); return val; }
//RCU
#define rcu_assign_pointer(a,b) ((a) = (b))
#define rcu_dereference(X) ((X))
#define rcu_dereference_protected(X, LOCK) ((X))
#define rcu_read_lock()
#define rcu_read_unlock()
#define __bitwise__
#define __must_check
#define __user
#define __kernel
#define __safe
#define __force
#define __nocast
#define __iomem
#define __chk_user_ptr(x) (void)0
#define __chk_io_ptr(x) (void)0
#define __builtin_warning(x, y...) (1)
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#define __acquire(x) (void)0
#define __release(x) (void)0
#define __cond_lock(x,c) (c)
#define __percpu
#define __rcu
#define __read_mostly
#define __devinitdata
#define __devinit
#define __devexit_p(X) (X)
#define ____cacheline_aligned_in_smp __rte_cache_aligned
#define EXPORT_SYMBOL(X)
#define EXPORT_SYMBOL_GPL(X)
#define MODULE_AUTHOR(X)
#define MODULE_DESCRIPTION(X)
#define MODULE_LICENSE(X)
#define MODULE_VERSION(X)

#define __pure                          __attribute__((pure))
#define __aligned(x)                    __attribute__((aligned(x)))
#define __printf(a, b)                  __attribute__((format(printf, a, b)))
#define __scanf(a, b)                   __attribute__((format(scanf, a, b)))
#define  noinline                       __attribute__((noinline))
//#define __attribute_const__             __attribute__((__const__))
#define __maybe_unused                  __attribute__((unused))
#define __always_unused                 __attribute__((unused))

#define MAX_MSIX_NUMBER 1024
#define MAX_IRQ_NUMBER 16
#define MAX_IRQ_DESC 256


#define ETH_ALEN (6)
#define PAGE_SIZE (4096)
#define PAGE_SHIFT (12)
#define PAGE_MASK       (~(PAGE_SIZE-1))
#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL
#define VLAN_N_VID              4096

//#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS		 */
#define VLAN_HLEN       4
#define VLAN_ETH_HLEN   18

#define __ALIGN_KERNEL(x, a)            __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)    (((x) + (mask)) & ~(mask))
#define __ALIGN_MASK(x, mask)   __ALIGN_KERNEL_MASK((x), (mask))
#define ALIGN(x, a)             __ALIGN_KERNEL((x), (a))
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PTR_ALIGN(p, a)         ((typeof(p))ALIGN((unsigned long)(p), (a)))
#define IS_ALIGNED(x, a)                (((x) & ((typeof(x))(a) - 1)) == 0)
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define DIV_ROUND_CLOSEST(x, divisor)(                  \
		{                                                       \
	typeof(divisor) __divisor = divisor;            \
	(((x) + ((__divisor) / 2)) / (__divisor));      \
		}                                                       \
)
#define mdelay(X) rte_delay_ms(X)
#define msleep_interruptible(X) mdelay(X)	// TODO: double checked
#define udelay(X) rte_delay_us(X)
#define msleep(X) rte_delay_ms(X)

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

/* Plain integer GFP bitmasks. Do not use this directly. */
#define ___GFP_DMA              0x01u
#define ___GFP_HIGHMEM          0x02u
#define ___GFP_DMA32            0x04u
#define ___GFP_MOVABLE          0x08u
#define ___GFP_WAIT             0x10u
#define ___GFP_HIGH             0x20u
#define ___GFP_IO               0x40u
#define ___GFP_FS               0x80u
#define ___GFP_COLD             0x100u
#define ___GFP_NOWARN           0x200u
#define ___GFP_REPEAT           0x400u
#define ___GFP_NOFAIL           0x800u
#define ___GFP_NORETRY          0x1000u
#define ___GFP_MEMALLOC         0x2000u
#define ___GFP_COMP             0x4000u
#define ___GFP_ZERO             0x8000u
#define ___GFP_NOMEMALLOC       0x10000u
#define ___GFP_HARDWALL         0x20000u
#define ___GFP_THISNODE         0x40000u
#define ___GFP_RECLAIMABLE      0x80000u
#define ___GFP_NOTRACK          0x200000u
#define ___GFP_NO_KSWAPD        0x400000u
#define ___GFP_OTHER_NODE       0x800000u
#define ___GFP_WRITE            0x1000000u
/* If the above are modified, __GFP_BITS_SHIFT may need updating */

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX          0x15b3
#endif

/*
 * GFP bitmasks..
 *
 * Zone modifiers (see linux/mmzone.h - low three bits)
 *
 * Do not put any conditional on these. If necessary modify the definitions
 * without the underscores and use them consistently. The definitions here may
 * be used in bit comparisons.
 */
#define __GFP_DMA       ((__force gfp_t)___GFP_DMA)
#define __GFP_HIGHMEM   ((__force gfp_t)___GFP_HIGHMEM)
#define __GFP_DMA32     ((__force gfp_t)___GFP_DMA32)
#define __GFP_MOVABLE   ((__force gfp_t)___GFP_MOVABLE)  /* Page is movable */
#define GFP_ZONEMASK    (__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)
/*
 * Action modifiers - doesn't change the zoning
 *
 * __GFP_REPEAT: Try hard to allocate the memory, but the allocation attempt
 * _might_ fail.  This depends upon the particular VM implementation.
 *
 * __GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 * cannot handle allocation failures.  This modifier is deprecated and no new
 * users should be added.
 *
 * __GFP_NORETRY: The VM implementation must not retry indefinitely.
 *
 * __GFP_MOVABLE: Flag that this page will be movable by the page migration
 * mechanism or reclaimed
 */
#define __GFP_WAIT      ((__force gfp_t)___GFP_WAIT)    /* Can wait and reschedule? */
#define __GFP_HIGH      ((__force gfp_t)___GFP_HIGH)    /* Should access emergency pools? */
#define __GFP_IO        ((__force gfp_t)___GFP_IO)      /* Can start physical IO? */
#define __GFP_FS        ((__force gfp_t)___GFP_FS)      /* Can call down to low-level FS? */
#define __GFP_COLD      ((__force gfp_t)___GFP_COLD)    /* Cache-cold page required */
#define __GFP_NOWARN    ((__force gfp_t)___GFP_NOWARN)  /* Suppress page allocation failure warning */
#define __GFP_REPEAT    ((__force gfp_t)___GFP_REPEAT)  /* See above */
#define __GFP_NOFAIL    ((__force gfp_t)___GFP_NOFAIL)  /* See above */
#define __GFP_NORETRY   ((__force gfp_t)___GFP_NORETRY) /* See above */
#define __GFP_MEMALLOC  ((__force gfp_t)___GFP_MEMALLOC)/* Allow access to emergency reserves */
#define __GFP_COMP      ((__force gfp_t)___GFP_COMP)    /* Add compound page metadata */
#define __GFP_ZERO      ((__force gfp_t)___GFP_ZERO)    /* Return zeroed page on success */
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC) /* Don't use emergency reserves.
 * This takes precedence over the
 * __GFP_MEMALLOC flag if both are
 * set
 */
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL) /* Enforce hardwall cpuset memory allocs */
#define __GFP_THISNODE  ((__force gfp_t)___GFP_THISNODE)/* No fallback, no policies */
#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE) /* Page is reclaimable */
#define __GFP_NOTRACK   ((__force gfp_t)___GFP_NOTRACK)  /* Don't track with kmemcheck */

#define __GFP_NO_KSWAPD ((__force gfp_t)___GFP_NO_KSWAPD)
#define __GFP_OTHER_NODE ((__force gfp_t)___GFP_OTHER_NODE) /* On behalf of other node */
#define __GFP_WRITE     ((__force gfp_t)___GFP_WRITE)   /* Allocator intends to dirty page */

/*
 * This may seem redundant, but it's a way of annotating false positives vs.
 * allocations that simply cannot be supported (e.g. page tables).
 */
#define __GFP_NOTRACK_FALSE_POSITIVE (__GFP_NOTRACK)

#define __GFP_BITS_SHIFT 25     /* Room for N __GFP_FOO bits */
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

/* This equals 0, but use constants in case they ever change */
#define GFP_NOWAIT      (GFP_ATOMIC & ~__GFP_HIGH)
/* GFP_ATOMIC means both !wait (__GFP_WAIT not set) and use emergency pool */
#define GFP_ATOMIC      (__GFP_HIGH)
#define GFP_NOIO        (__GFP_WAIT)
#define GFP_NOFS        (__GFP_WAIT | __GFP_IO)
#define GFP_KERNEL      (__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_TEMPORARY   (__GFP_WAIT | __GFP_IO | __GFP_FS | \
		__GFP_RECLAIMABLE)
#define GFP_USER        (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_HIGHUSER    (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | \
		__GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE    (__GFP_WAIT | __GFP_IO | __GFP_FS | \
		__GFP_HARDWALL | __GFP_HIGHMEM | \
		__GFP_MOVABLE)
#define GFP_IOFS        (__GFP_IO | __GFP_FS)
#define GFP_TRANSHUGE   (GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
		__GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN | \
		__GFP_NO_KSWAPD)

#include "list.h"


enum module_param_type
{
	param_type_uint,
	param_type_int,
	param_type_string,
	param_type_ushort,
	param_type_none,
};

typedef struct
{
	struct list_head list;
	const char* name;
	void* ptr;
	int ptr_size;
	int elt_size;
	enum module_param_type param_type;
	int permission;
	const char* description;
}__module_param_t;


#define __init
#define __exit

#define __MODULE_STRING_1(x)    #x
#define __MODULE_STRING(x)      __MODULE_STRING_1(x)

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

//#define MODULE_PARM(A) MODULE_PARM_DESC(A, "")
#define module_param(name, type, perm) \
		module_param_named(name, name, type, perm)


#define module_param_string(_name, _variable, _size, _permission) \
		static __module_param_t __module_param_ ## _name \
		= { .name = #_name, .param_type = param_type_string, .ptr = &_variable, .permission = _permission, .ptr_size = _size, .elt_size = 1}; \
		void __module_param_init_func__ ## _name(void); \
		void __attribute__((constructor, used)) __module_param_init_func__ ## _name(void) \
		{ \
			register_module_parameter(&__module_param_ ## _name); \
		}

#define module_param_named(_name, _variable, _type, _permission) \
		static __module_param_t __module_param_ ## _name \
		= { .name = #_name, .param_type = param_type_ ## _type, .ptr = &_variable, .permission = _permission, .ptr_size = sizeof(_type), .elt_size = sizeof(_type)}; \
		void __module_param_init_func__ ## _name(void); \
		void __attribute__((constructor, used)) __module_param_init_func__ ## _name(void) \
		{ \
			register_module_parameter(&__module_param_ ## _name); \
		}

#define MODULE_PARM(A,B) MODULE_PARM_DESC(A,B)

#define MODULE_PARM_DESC(_name, _description_string) \
		void __module_param_desc_func__ ## _name(void); \
		void __attribute__((constructor, used)) __module_param_desc_func__ ## _name(void) \
		{ \
			register_module_parameter_desc(&__module_param_ ## _name, _description_string); \
		}

#define module_param_array(_variable, _type, nump, _permission) module_param_array_named(_variable, _variable, _type, nump, _permission)

#define module_param_array_named(_name, _variable, _type, nump, _permission) \
		static __module_param_t __module_param_ ## _name \
		= { .name = #_name, .param_type = param_type_ ## _type, .ptr = &_variable, .permission = _permission, .ptr_size = sizeof(_variable), .elt_size = sizeof(_variable[0])}; \
		void __module_param_init_func__ ## _name(void); \
		void __attribute__((constructor, used)) __module_param_init_func__ ## _name(void) \
		{ \
			*(nump) = sizeof(_variable[0]); \
			register_module_parameter(&__module_param_ ## _name); \
		}



//end module def

typedef rte_spinlock_t mutex_t;
typedef rte_spinlock_t spinlock_t;
typedef rte_atomic32_t atomic_t;
typedef rte_spinlock_t rwlock_t;

#define ATOMIC_INIT(X) RTE_ATOMIC32_INIT(X)

#define DEFINE_MUTEX(_mutex) \
		rte_spinlock_t _mutex = {.locked=0}

#define mmiowb() rte_wmb()
#define wmb() rte_wmb()
#define mb() rte_mb()
#define rmb() rte_rmb()
#define read_barrier_depends() rte_rmb()
#define smp_mb() rte_mb()
#define smp_wmb() rte_wmb()
#define smp_rmb() rte_rmb()
#define smp_mb__before_atomic() barrier()
#define smp_mb__before_clear_bit() barrier()
#define synchronize_rcu() rte_mb()
#define synchronize_irq(X) rte_mb()
#define synchronize_rcu_expedited() rte_mb()
//#define timecounter_cyc2time(X, Y) (Y)
#define timecounter_cyc2time(clock, timestamp) (timestamp)
#define timecounter_read(clock)
#define timecounter_init(a,b,c)
#define time_is_before_jiffies(X) (jiffies > (X))

#define prefetch(ptr) rte_prefetch0(ptr)
#define prefetchw(ptr) rte_prefetch0(ptr)
//#define HZ (rte_get_tsc_hz())
#ifndef HZ
#define HZ 1000UL //1000 Hz
#endif
#define jiffies (HZ*rte_rdtsc()/rte_get_tsc_hz())

#define round_jiffies(x) (x)
#define round_jiffies_relative(x) (x)

#define spin_lock_init(X) rte_spinlock_init((mutex_t*)X)
#define spin_lock(X) rte_spinlock_lock((mutex_t*)X)
#define spin_unlock(X) rte_spinlock_unlock((mutex_t*)X)

#define spin_lock_irq spin_lock
#define spin_unlock_irq spin_unlock
#define spin_lock_irqsave(X,flag) spin_lock(X)
#define spin_unlock_irqrestore(X,flag) spin_unlock(X)
#define spin_lock_bh(X) spin_lock(X)
#define spin_unlock_bh(X) spin_unlock(X)

#define mutex_init(X) rte_spinlock_init((mutex_t*)X)
#define mutex_lock(X) rte_spinlock_lock((mutex_t*)X)
#define mutex_unlock(X) rte_spinlock_unlock((mutex_t*)X)
#define mutex_destroy(X)

#define rwlock_init(X) rte_spinlock_init(X)
#define read_lock(X) rte_spinlock_lock(X)
#define read_unlock(X) rte_spinlock_unlock(X)
#define write_lock(X) rte_spinlock_lock(X)
#define write_unlock(X) rte_spinlock_unlock(X)
#define read_lock_irqsave(X,flag) rte_spinlock_lock(X)
#define read_unlock_irqrestore(X,flag) rte_spinlock_unlock(X)
#define write_lock_irqsave(X,flag) rte_spinlock_lock(X)
#define write_unlock_irqrestore(X,flag) rte_spinlock_unlock(X)

#define readb read8
#define writeb write8
#define readw read16
#define writew write16
#define readl read32
#define writel write32
#define readq read64
#define writeq write64

#define kmalloc(size, flag) rte_malloc("kmalloc", size, RTE_CACHE_LINE_SIZE)
#define kzalloc(size, flag) rte_zmalloc("kzalloc", size, RTE_CACHE_LINE_SIZE)
#define kcalloc(count, unit, kern_flag) rte_calloc("kcalloc", count, unit, RTE_CACHE_LINE_SIZE)
#define kmalloc_node(size, flag, node) rte_malloc_socket("kmalloc_node", size, RTE_CACHE_LINE_SIZE, node)
#define kzalloc_node(size, kern_flag, node) rte_zmalloc_socket("kzalloc_node", size, RTE_CACHE_LINE_SIZE, node)
#define vzalloc(size) rte_zmalloc("vzalloc", size, RTE_CACHE_LINE_SIZE)
#define vzalloc_node(size, node) rte_zmalloc_socket("vzalloc", size, RTE_CACHE_LINE_SIZE, node)
#define vfree(ptr) rte_free(ptr)
#define vmalloc(size) rte_malloc("vmalloc", size, RTE_CACHE_LINE_SIZE)
#define vmalloc_node(size, node) rte_malloc_socket("vmalloc", size, RTE_CACHE_LINE_SIZE, node)

#define kfree(ptr) rte_free(ptr)

#define L1_CACHE_BYTES RTE_CACHE_LINE_SIZE
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#define cache_line_size(X) RTE_CACHE_LINE_SIZE

#define atomic_cmpset(a,b,c) rte_atomic32_cmpset(a,b,c)
#define atomic_init(a) rte_atomic32_init(a)
#define atomic_set(a,b) rte_atomic32_set(a,b)
#define atomic_read(a) rte_atomic32_read(a)
#define atomic_add(a,b) rte_atomic32_add(b,a)
#define atomic_sub(a,b) rte_atomic32_sub(b,a)
#define atomic_inc(a) rte_atomic32_inc(a)
#define atomic_dec(a) rte_atomic32_dec(a)
#define atomic_add_return(a,b) rte_atomic32_add_return(b,a)
#define atomic_inc_return(a) rte_atomic32_add_return(a,1)
#define atomic_dec_return(a) rte_atomic32_add_return(a,-1)
#define atomic_inc_and_test(a) rte_atomic32_inc_and_test(a)
#define atomic_dec_and_test(a) rte_atomic32_dec_and_test(a)
#define atomic_test_and_set(a) rte_atomic32_test_and_set(a)
#define atomic_clear(a) rte_atomic32_clear(a)
#define cond_resched() rte_pause()

#define jiffies_to_msecs(X) (MSEC_PER_SEC*(X)/HZ)

#define max __MAX
#define min __MIN
#define MAX __MAX
#define MIN __MIN
#define __MAX(a,b) RTE_MAX((a),(b))
#define __MIN(a,b) RTE_MIN((a),(b))
#define min3(a,b,c) RTE_MIN(RTE_MIN((a),(b)),(c))
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define min_t(type, a, b) MIN((type)(a), (type)(b))
#define max_t(type, a, b) MAX((type)(a), (type)(b))

//

#define __always_inline __inline __attribute__ ((__always_inline__))
#define __packed __attribute__((packed))

#define time_get_ts(p_timespec) (clock_gettime(CLOCK_MONOTONIC_RAW, p_timespec))

#define msecs_to_jiffies(msec) ((msec * HZ) / MSEC_PER_SEC)
#define jiffies_to_msec(jifi) ((jifi*MSEC_PER_SEC) / HZ)

#define __raw_writeq write64

struct mutex{
	mutex_t mutex;
}__attribute__((packed));

typedef struct semaphore
{
	int count;
	mutex_t lock;
}semaphore_t;
#define rw_semaphore semaphore
#define down_read down
#define up_read up
#define down_write down
#define up_write up
#define init_rwsem(x) sema_init(x,1)

#define KERN_EMERG "[KERN_EMERG]"
#define KERN_ALERT "[KERN_ALERT]"
#define KERN_CRIT "[KERN_CRIT]"
#define KERN_ERR "[KERN_ERR]"
#define KERN_WARNING "[KERN_WARNING]"
#define KERN_NOTICE "[KERN_NOTICE]"
#define KERN_DEBUG "[KERN_DEBUG]"
#define KERN_INFO "[KERN_INFO]"

#define printk printf
#define printk_once printf
#define si_meminfo(ptr) sysinfo(ptr)

#define dev_printk(PRINT_LEVEL, device, format, arg...) \
		do { \
			printf("[dev_printk] "); \
			printf(format, ##arg); \
		} while(0)

#define dev_err(device, format, arg...) \
		do { \
			printf("[dev_err] "); \
			printf(format, ##arg); \
		} while(0)

#define dev_info(device, format, arg...) \
		do { \
			printf("[dev_info] "); \
			printf(format, ##arg); \
		} while(0)

#define dev_warn(device, format, arg...) \
		do { \
			printf("[dev_warn] "); \
			printf(format, ##arg); \
		} while(0)

#define pr_warning(format, arg...) \
		do { \
			printf("[pr_warning] "); \
			printf(format, ##arg); \
		} while(0)

#define pr_warn(format, arg...) \
		do { \
			printf("[pr_warn] "); \
			printf(format, ##arg); \
		} while(0)

#define pr_debug(format, arg...) \
		do { \
			printf("[pr_debug] "); \
			printf(format, ##arg); \
		} while(0)

#define pr_info(format, arg...) \
		do { \
			printf("[pr_info] "); \
			printf(format, ##arg); \
		} while(0)

#define pr_err(format, arg...) \
		do { \
			printf("[pr_err] "); \
			printf(format, ##arg); \
		} while(0)

#define pr_devel(format, arg...) \
		do { \
			printf("[pr_devel] "); \
			printf(format, ##arg); \
		} while(0)

# define do_div(n,base) ({                                      \
		uint64_t __rem;                                         \
		__rem = ((uint64_t)(n)) % (base);                       \
		(n) = ((uint64_t)(n)) / (base);                         \
		__rem;                                                  \
		})

#define dev_dbg(dev, format, arg...)                            \
		({                                                              \
			if (0)                                                  \
			dev_printk(KERN_DEBUG, dev, format, ##arg);     \
			0;                                                      \
		})

#define __raw_writel write32
#define __raw_readl read32
#define writel write32
#define readl read32

#define BUG_ON(X) assert(!(X))


#define MAX_ERRNO       4095


#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

static inline bool __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void * __must_check ERR_CAST(__force const void *ptr)
{
	/* cast away the const */
	return (void *) ptr;
}

static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

/* Deprecated */
#define PTR_RET(p) PTR_ERR_OR_ZERO(p)



enum {
	NETIF_MSG_DRV           = 0x0001,
	NETIF_MSG_PROBE         = 0x0002,
	NETIF_MSG_LINK          = 0x0004,
	NETIF_MSG_TIMER         = 0x0008,
	NETIF_MSG_IFDOWN        = 0x0010,
	NETIF_MSG_IFUP          = 0x0020,
	NETIF_MSG_RX_ERR        = 0x0040,
	NETIF_MSG_TX_ERR        = 0x0080,
	NETIF_MSG_TX_QUEUED     = 0x0100,
	NETIF_MSG_INTR          = 0x0200,
	NETIF_MSG_TX_DONE       = 0x0400,
	NETIF_MSG_RX_STATUS     = 0x0800,
	NETIF_MSG_PKTDATA       = 0x1000,
	NETIF_MSG_HW            = 0x2000,
	NETIF_MSG_WOL           = 0x4000,
};


#include "kcompat.h"
#include "inline_functions.h"
#include "etherdevice.h"
#include "netdev_features.h"

#endif /* DRIVERS_NET_MLNX_UIO_INCLUDE_KMOD_H_ */
