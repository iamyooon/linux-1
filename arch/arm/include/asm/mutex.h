/*
 * arch/arm/include/asm/mutex.h
 *
 * ARM optimized mutex locking primitives
 *
 * Please look into asm-generic/mutex-xchg.h for a formal definition.
 */
#ifndef _ASM_MUTEX_H
#define _ASM_MUTEX_H
/*
 * On pre-ARMv6 hardware this results in a swp-based implementation,
 * which is the most efficient. For ARMv6+, we have exclusive memory
 * accessors and use atomic_dec to avoid the extra xchg operations
 * on the locking slowpaths.
 armv6 이전에는 swp 기반으로 구현하는게 효과적이고..
 armv7부터는 atomic_dec를 사용하고 xchg 동작은 피하고 있음.
 */
#if __LINUX_ARM_ARCH__ < 6
#include <asm-generic/mutex-xchg.h>
#else
#include <asm-generic/mutex-dec.h>
#endif
#endif	/* _ASM_MUTEX_H */
