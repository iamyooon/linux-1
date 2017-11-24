/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TYPECHECK_H_INCLUDED
#define TYPECHECK_H_INCLUDED

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
// compile-time에 변수 x의 타입이 type과 같은지 비교함. 다르면 컴파일에러
#define typecheck(type,x) \
({	type __dummy; \		// type형 변수 __dummy 정의
	typeof(x) __dummy2; \	// 변수 x의 type형 변수 __dummy2 정의
	(void)(&__dummy == &__dummy2); \ // 타입이 다른 두 변수를 비교하면 warning이 발생하거나 
					 // -Werror를 사용하면 error가 발생할 것임. 이걸로 체크..
					 // 타입이 같으면 void형 값으로 캐스팅이 될것이고 최적화에 의해
					 // 제거될것임.
	1; \				 // 결과적으로 타입이 같으면 1을 리턴함. 리턴된 값은 
					 // 비교문에서는 참으로 사용되고 다른곳에서는 무시됨..
})

/*
 * Check at compile time that 'function' is a certain type, or is a pointer
 * to that type (needs to use typedef for the function type.)
 */
#define typecheck_fn(type,function) \
({	typeof(type) __tmp = function; \
	(void)__tmp; \
})

#endif		/* TYPECHECK_H_INCLUDED */
