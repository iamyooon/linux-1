/*
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_IRQFLAGS_H
#define __ASM_IRQFLAGS_H

#ifdef __KERNEL__

#include <asm/ptrace.h>

/*
 * CPU interrupt mask handling.
 */
// 인터럽트를 비활성화하고 DAIF 필드를 flags에 저장함.
static inline unsigned long arch_local_irq_save(void)
{
	unsigned long flags;
	asm volatile(
		"mrs	%0, daif		// arch_local_irq_save\n" // DAIF 필드값 읽어서 변수 flags에 저장
		"msr	daifset, #2"		// DAIF의 I비트를 설정함, 인터럽트 마스킹.
		: "=r" (flags)
		:
		: "memory");
	return flags;
}

// 인터럽트를 활성화함.
static inline void arch_local_irq_enable(void)
{
	asm volatile(
		"msr	daifclr, #2		// arch_local_irq_enable" // DAIF의 I비트 설정을 제거함, 인터럽트 언마스킹
		:
		:
		: "memory");
}

// DAIF의 I비트를 설정해서 인터럽트를 비활성화함.
static inline void arch_local_irq_disable(void)
{
	asm volatile(
		"msr	daifset, #2		// arch_local_irq_disable"
		:
		:
		: "memory");
}

#define local_fiq_enable()	asm("msr	daifclr, #1" : : : "memory")
#define local_fiq_disable()	asm("msr	daifset, #1" : : : "memory")

#define local_async_enable()	asm("msr	daifclr, #4" : : : "memory")
#define local_async_disable()	asm("msr	daifset, #4" : : : "memory")

/*
 * Save the current interrupt enable state.
 */
// 현재 DAIF 값을 리턴함.
static inline unsigned long arch_local_save_flags(void)
{
	unsigned long flags;
	asm volatile(
		"mrs	%0, daif		// arch_local_save_flags"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}

/*
 * restore saved IRQ state
 */
// @flags에 저장된 DAIF 값을 복원함.
static inline void arch_local_irq_restore(unsigned long flags)
{
	asm volatile(
		"msr	daif, %0		// arch_local_irq_restore"
	:
	: "r" (flags)
	: "memory");
}

// @flags값을 조사해서 인터럽트가 비활성화(I비트가 설정)되어 있는지 체크
static inline int arch_irqs_disabled_flags(unsigned long flags)
{
	return flags & PSR_I_BIT;
}

/*
 * save and restore debug state
 */
#define local_dbg_save(flags)						\
	do {								\
		typecheck(unsigned long, flags);			\
		asm volatile(						\
		"mrs    %0, daif		// local_dbg_save\n"	\
		"msr    daifset, #8"					\
		: "=r" (flags) : : "memory");				\
	} while (0)

#define local_dbg_restore(flags)					\
	do {								\
		typecheck(unsigned long, flags);			\
		asm volatile(						\
		"msr    daif, %0		// local_dbg_restore\n"	\
		: : "r" (flags) : "memory");				\
	} while (0)

#endif
#endif
