/* Generic task switch macro wrapper, based on MN10300 definitions.
 *
 * It should be possible to use these on really simple architectures,
 * but it serves more as a starting point for new ports.
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#ifndef __ASM_GENERIC_SWITCH_TO_H
#define __ASM_GENERIC_SWITCH_TO_H

#include <linux/thread_info.h>

/*
 * Context switching is now performed out-of-line in switch_to.S
 */
extern struct task_struct *__switch_to(struct task_struct *,
				       struct task_struct *);

// register set을 스위칭함. 
// prev의 register 정보는 prev의 thread_struct의 cpu_context 구조체에 백업
// next의 register 정보는 cpu_context 구조체에서 register로 복원함.
// stack pointer를 가리키는 sp_el0가 next의 stack을 가리키도록 설정함.
#define switch_to(prev, next, last)					\
	do {								\
		((last) = __switch_to((prev), (next)));			\
	} while (0)

#endif /* __ASM_GENERIC_SWITCH_TO_H */
