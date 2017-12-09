/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_BUILTIN_FLS_H_
#define _ASM_GENERIC_BITOPS_BUILTIN_FLS_H_

/**
 * fls - find last (most-significant) bit set
 * fls - 설정된 가장 최상위 비트 찾기
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
// 인자 @x에서 1로 설정된 최상위비트 번호를 리턴함.
static __always_inline int fls(int x)
{
	// 1) x가 0이 아니라면 최상위 비트에서 연속적으로 0으로 설정된 비트
	//    개수를 리턴하는 gcc의 builtin-function을 호출해서 인자 @x의 총 비트수에서
	//    빼서 리턴한다.
	// 2) x가 0이라면 리턴 0, gcc의 builtin function인 아래 함수는
	// x가 0인 경우의 동작이 정의되어 있지 않음. 커널에서 처리해야 함.
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

#endif
