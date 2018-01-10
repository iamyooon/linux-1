/*
 * Mutexes: blocking mutual exclusion locks
 *
 * started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * This file contains mutex debugging related internal declarations,
 * prototypes and inline functions, for the CONFIG_DEBUG_MUTEXES case.
 * More details are in kernel/mutex-debug.c.
 */

/*
 * This must be called with lock->wait_lock held.
 */
extern void debug_mutex_lock_common(struct mutex *lock,
				    struct mutex_waiter *waiter);
extern void debug_mutex_wake_waiter(struct mutex *lock,
				    struct mutex_waiter *waiter);
extern void debug_mutex_free_waiter(struct mutex_waiter *waiter);
extern void debug_mutex_add_waiter(struct mutex *lock,
				   struct mutex_waiter *waiter,
				   struct thread_info *ti);
extern void mutex_remove_waiter(struct mutex *lock, struct mutex_waiter *waiter,
				struct thread_info *ti);
extern void debug_mutex_unlock(struct mutex *lock);
extern void debug_mutex_init(struct mutex *lock, const char *name,
			     struct lock_class_key *key);

static inline void mutex_set_owner(struct mutex *lock)
{
	lock->owner = current;
}

static inline void mutex_clear_owner(struct mutex *lock)
{
	lock->owner = NULL;
}
/*
 * 1. 인터럽트 컨텍스트에서 spinlock을 잡으려 했다면 warning 출력
 * 2. irq disable and save
 * 3. spinlock 잡기
 * 4. spinlock의 owner인 mutex의 magic이 비정상이라면 warning 출력
 * irq enable은 spinlock을 릴리즈할 때 할것임..
 */
#define spin_lock_mutex(lock, flags)			\
	do {						\
		struct mutex *l = container_of(lock, struct mutex, wait_lock); \
							\
		DEBUG_LOCKS_WARN_ON(in_interrupt());	\
		local_irq_save(flags);			\
		arch_spin_lock(&(lock)->rlock.raw_lock);\
		DEBUG_LOCKS_WARN_ON(l->magic != l);	\
	} while (0)

/*
 * 1. spinlock 놓기
 * 2. irq enable and restore
 * 3. 선점이 필요하다면 선점을 시도함
 */
#define spin_unlock_mutex(lock, flags)				\
	do {							\
		arch_spin_unlock(&(lock)->rlock.raw_lock);	\
		local_irq_restore(flags);			\
		preempt_check_resched();			\
	} while (0)
