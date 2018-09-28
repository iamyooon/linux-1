/*
 * mm/low-mem-notify.c
 *
 * Sends low-memory notifications to processes via /dev/low-mem.
 *
 * Copyright (C) 2012 The Chromium OS Authors
 * This program is free software, released under the GPL.
 * Based on a proposal by Minchan Kim
 *
 * A process that polls /dev/low-mem is notified of a low-memory situation.
 * The intent is to allow the process to free some memory before the OOM killer
 * is invoked.
 *
 * A low-memory condition is estimated by subtracting anonymous memory
 * (i.e. process data segments), kernel memory, and a fixed amount of
 * file-backed memory from total memory.  This is just a heuristic, as in
 * general we don't know how much memory can be reclaimed before we try to
 * reclaim it, and that's too expensive or too late.
 *
 * This is tailored to Chromium OS, where a single program (the browser)
 * controls most of the memory, and (currently) no swap space is used.
 */


#include <linux/module.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/eventfd.h>
#include <linux/sort.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/oom.h>		// find_lock_task_mm()
#include <linux/blkdev.h>	// nr_blockdev_pages()

#include <linux/low-mem-notify.h>
#ifdef CONFIG_SWAP
#include <linux/swap.h>
#endif

#undef DEBUG
#ifdef DEBUG
#define dprintk(msg, args...)       \
		printk("\r\n[%s:%d:%s] " msg, __FILE__, __LINE__, __func__, ## args)
#else
#define dprintk(msg, args...)
#endif

#define K(x) ((x) << (PAGE_SHIFT - 10))

#define DEFAULT_RATIO			1

struct low_mem_threshold {
	struct eventfd_ctx *eventfd;
	unsigned long threshold;
	void (*k_callback)(unsigned long threshold);
	unsigned long last_jiffies;
};

struct low_mem_threshold_ary {
	int prev_threshold;
	int current_threshold;
	unsigned int size;
	struct low_mem_threshold entries[0];
};

struct low_mem_thresholds {
	/* Primary thresholds array */
	struct low_mem_threshold_ary *primary;
	/* Spare threshold array */
	struct low_mem_threshold_ary *spare;
};

/* protect arrays of thresholds */
struct mutex thresholds_lock;

/* thresholds for memory usage. RCU-protected */
struct low_mem_thresholds thresholds;

/* ratio */
atomic_t ratio;

/* extra raclaimable list */
static LIST_HEAD(xr_list);

/* zram swap */
atomic_t zramswap;

/* freeze flag */
atomic_t freeze;

/*
 * threshold walking feature
 * In the current implementation, if the current threshold is changed
 * more than one level, it will process two or more thresholds in turn.
 *
 * However, in some cases the process of change is not important and
 * only the end result is important. We added a threshold walking feature
 * to handle this case. default is true.
 */
static int threshold_walking = 1;

/*
 * jittering prevention feature
 * if this feature is enabled, jittering between buddy threshold is prevented.
 */
static int prevent_jittering = 0;

static void low_mem_notify_threshold(int force);
static unsigned long total_pages;

int low_mem_register_event(struct eventfd_ctx *eventfd, unsigned long threshold,
						void (*callback)(unsigned long));

static void def_callback(unsigned long threshold)
{
	printk("%s current usable page is met to %ld\n", __func__, threshold);
}

static void reg_basic_callback(void)
{
	int total_pages = totalram_pages + total_swap_pages;
	int min_unit = total_pages/20;

	/* notification for 100% usable pages */
	low_mem_register_event(NULL, min_unit*20, def_callback);
	/* notification for 90% usable pages */
	low_mem_register_event(NULL, min_unit*18, def_callback);
	/* notification for 80% usable pages */
	low_mem_register_event(NULL, min_unit*16, def_callback);
	/* notification for 70% usable pages */
	low_mem_register_event(NULL, min_unit*14, def_callback);
	/* notification for 60% usable pages */
	low_mem_register_event(NULL, min_unit*12, def_callback);
	/* notification for 50% usable pages */
	low_mem_register_event(NULL, min_unit*10, def_callback);
	/* notification for 40% usable pages */
	low_mem_register_event(NULL, min_unit*8, def_callback);
	/* notification for 30% usable pages */
	low_mem_register_event(NULL, min_unit*6, def_callback);
	/* notification for 20% usable pages */
	low_mem_register_event(NULL, min_unit*4, def_callback);
	/* notification for 10% usable pages */
	low_mem_register_event(NULL, min_unit*2, def_callback);
	/* notification for 5% usable pages */
	low_mem_register_event(NULL, min_unit*1, def_callback);
}

static int need_to_skip(struct low_mem_threshold_ary *array, int next)
{
	int prev = array->prev_threshold;
	int curr = array->current_threshold;

	unsigned long last_jiffies = array->entries[curr].last_jiffies;
	unsigned long timeout = msecs_to_jiffies(60*1000);

	if (!prevent_jittering)
		return 0;

	if (prev != next)
		return 0;

	if (curr-1 != next && curr+1 != next)
		return 0;

	if (time_after_eq(jiffies, last_jiffies + timeout)){
		return 0;
	}

	return 1;
}


void low_mem_notify(void)
{
	if (atomic_read(&freeze))
		return;

	low_mem_notify_threshold(0);
}

static unsigned long get_reserved_pages(void)
{
	return totalreserve_pages;
}

static unsigned long get_free_pages(void)
{
	return global_page_state(NR_FREE_PAGES);
}

static unsigned long get_shmem_pages(void)
{
	return global_page_state(NR_SHMEM);
}

static unsigned long get_file_pages(void)
{
	return global_page_state(NR_FILE_PAGES);
}

static unsigned long get_slab_reclaimable_pages(void)
{
	return global_page_state(NR_SLAB_RECLAIMABLE);
}

static unsigned long get_slab_unreclaimable_pages(void)
{
	return global_page_state(NR_SLAB_UNRECLAIMABLE);
}

static unsigned long get_swap_pages(void)
{
#ifdef CONFIG_SWAP
	return atomic_long_read(&nr_swap_pages);
#else
	return 0;
#endif
}

static unsigned long get_swapcache_pages(void)
{
#ifdef CONFIG_SWAP
	return total_swapcache_pages();
#else
	return 0;
#endif
}

static unsigned long get_zramswap_pages(void)
{
#ifdef CONFIG_SWAP
	if (atomic_read(&zramswap))
		return (get_swap_pages()/3);
	else
		return 0;
#else
	return 0;
#endif
}

static void show_migration_types(unsigned char type)
{
        static const char types[MIGRATE_TYPES] = {
                [MIGRATE_UNMOVABLE]     = 'U',
                [MIGRATE_RECLAIMABLE]   = 'E',
                [MIGRATE_MOVABLE]       = 'M',
                [MIGRATE_RESERVE]       = 'R',
#ifdef CONFIG_CMA
                [MIGRATE_CMA]           = 'C',
#endif
#ifdef CONFIG_MEMORY_ISOLATION
                [MIGRATE_ISOLATE]       = 'I',
#endif
        };
        char tmp[MIGRATE_TYPES + 1];
        char *p = tmp;
        int i;

        for (i = 0; i < MIGRATE_TYPES; i++) {
                if (type & (1 << i))
                        *p++ = types[i];
        }

        *p = '\0';
        printk("(%s) ", tmp);
}

static void show_freemem_info(void)
{
	struct zone *zone;

        for_each_populated_zone(zone) {
                unsigned int order;
                unsigned long nr[MAX_ORDER], flags, total = 0;
                unsigned char types[MAX_ORDER];

                printk("%s: ", zone->name);

                spin_lock_irqsave(&zone->lock, flags);
                for (order = 0; order < MAX_ORDER; order++) {
                        struct free_area *area = &zone->free_area[order];
                        int type;

                        nr[order] = area->nr_free;
                        total += nr[order] << order;

                        types[order] = 0;
                        for (type = 0; type < MIGRATE_TYPES; type++) {
                                if (!list_empty(&area->free_list[type]))
                                        types[order] |= 1 << type;
                        }
                }
                spin_unlock_irqrestore(&zone->lock, flags);
                for (order = 0; order < MAX_ORDER; order++) {
                        printk("%lu*%lukB ", nr[order], K(1UL) << order);
                        if (nr[order])
                                show_migration_types(types[order]);
                }
                printk("= %lukB\n", K(total));
        }
}

static void show_process_rss_info(void)
{
	struct task_struct *p;
	struct task_struct *task;

	printk("[lmn] process's rss info\n");
	printk("[lmn] %27s %7s\n", "name(pid)", "rss");

	rcu_read_lock();
	for_each_process(p) {
		if (p->flags & PF_KTHREAD)
			continue;

		task = find_lock_task_mm(p);
		if (!task) {
			continue;
		}
		printk("[lmn] %20s(%5d) %7ldKB\n",
			task->comm, task->pid, K(get_mm_rss(task->mm)));
		task_unlock(task);
	}
	rcu_read_unlock();
}

static void show_summary_meminfo(unsigned long threshold)
{
	unsigned long total     = totalram_pages;
	unsigned long free      = get_free_pages();
	unsigned long buffer    = nr_blockdev_pages();
	unsigned long file      = get_file_pages();
	unsigned long slab      = get_slab_reclaimable_pages() +
				  get_slab_unreclaimable_pages();
	unsigned long swapcache = get_swapcache_pages();
	unsigned long cached    = file - swapcache - buffer;
	unsigned long available = 0;
	unsigned long wmark_low = 0;
	unsigned long pagecache = 0;
	unsigned long anon      = 0;
	unsigned long count     = 0;

	unsigned long pages[NR_LRU_LISTS] = {0,};
	struct zone *zone;
	char buf[256] = {0,};
	int lru = 0;

	if (cached < 0)
		cached = 0;

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_page_state(NR_LRU_BASE + lru);

	for_each_zone(zone)
		wmark_low += zone->watermark[WMARK_LOW];

	pagecache = pages[LRU_ACTIVE_FILE] + pages[LRU_INACTIVE_FILE];
	pagecache -= min(pagecache / 2, wmark_low);

	available = free - wmark_low + pagecache + global_page_state(NR_SLAB_RECLAIMABLE)
		- min(global_page_state(NR_SLAB_RECLAIMABLE) / 2, wmark_low);
	if (available < 0)
		available = 0;

	anon = pages[LRU_ACTIVE_ANON] + pages[LRU_INACTIVE_ANON];

	count  = sprintf(buf, "[lmn]   Total     Free    Avail   Cached     Anon     File     Slab\n");
	count += sprintf(&buf[count], "%s %6luK %7luK %7luK %7luK %7luK %7luK %7luK\n",
			"[lmn]", K(total), K(free), K(available), K(cached), K(anon), K(file), K(slab));
	printk("%s", buf);
	return;
}

static inline unsigned long _free_pages(void)
{
	unsigned long free = get_free_pages();
	unsigned long reserved = get_reserved_pages();
	unsigned long file = get_file_pages();
	unsigned long shmem = get_shmem_pages();
	unsigned long swap = get_swap_pages();
	unsigned long swapcache = get_swapcache_pages();

	free += swap - reserved;
	file -= swapcache - shmem;

	return (free > file) ? free : file;
}

static inline unsigned long _usable_pages(void)
{
	unsigned long free = get_free_pages();
	unsigned long reserved = get_reserved_pages();
	unsigned long file = get_file_pages();
	unsigned long shmem = get_shmem_pages();
	unsigned long swap = get_swap_pages();
	unsigned long swapcache = get_swapcache_pages();
	unsigned long slab_reclaimable = get_slab_reclaimable_pages();
	unsigned long zramuse = get_zramswap_pages();
	unsigned long usable;

	usable = free + file + swap + slab_reclaimable - swapcache - zramuse - reserved - shmem;
	return ((long)usable > 0) ? usable : 0;
}

static void handle_lowmem_event(struct low_mem_threshold entry)
{
	if (entry.eventfd)
		eventfd_signal(entry.eventfd, 1);
	else if(entry.k_callback)
		entry.k_callback(entry.threshold);
	else
		dprintk("eventfd and k_callback are NULL\n");
}

static void handle_and_update(struct low_mem_threshold_ary *t, int i)
{
	handle_lowmem_event(t->entries[i]);
	t->entries[i].last_jiffies = jiffies;
}

static void low_mem_notify_threshold(int force)
{
	struct low_mem_threshold_ary *t;
	unsigned long threshold;
	unsigned long free;
	int max_idx;
	int i;

	rcu_read_lock();
	t = rcu_dereference(thresholds.primary);
	if (!t)
		goto unlock;

	i = t->current_threshold;
	if (i < 0)
		goto unlock;

	max_idx = t->size - 1;
	threshold = t->entries[i].threshold;
	free = _usable_pages(); /* _free_pages(); */

	if (force)
		handle_and_update(t, i);

	/*
	 * fastpath - still in current threshold
	 */
	if (threshold <= free) {
		if (i < max_idx && free < t->entries[i+1].threshold)
			goto unlock;
		if (i == max_idx)
			goto unlock;
	}

	/*
	 * slowpath - need to search proper threshold
	 */
	for (; i >= 0 && unlikely(t->entries[i].threshold > free); i--)
		if (threshold_walking && !need_to_skip(t, i))
			handle_and_update(t, i);

	i++;

	for (; i < t->size && unlikely(t->entries[i].threshold <= free); i++)
		if (threshold_walking && !need_to_skip(t, i))
			handle_and_update(t, i);

	if (!threshold_walking && !need_to_skip(t, i - 1))
		handle_and_update(t, i - 1);

	t->prev_threshold = t->current_threshold;
	t->current_threshold = i - 1;

unlock:
	rcu_read_unlock();
}

static int compare_thresholds(const void *a, const void *b)
{
	const struct low_mem_threshold *_a = a;
	const struct low_mem_threshold *_b = b;

	if (_a->threshold > _b->threshold)
		return 1;

	if (_a->threshold < _b->threshold)
		return -1;

	return 0;
}

/**
 * low_mem_register_event - register low memory event
 * @eventfd: event file descriptor, kernel doesn't use eventfd(NULL) but kcallback
 * @threshold: memory threshold value(unit.page count)
 * @callback: function pointer for kernel handler, userspace doesn`t use
 *            kcallback(NULL) but eventfd.
 *
 * Return 0, if registration success
 * Return -ENOMEM, if kmalloc() fail
 */
int low_mem_register_event(struct eventfd_ctx *eventfd, unsigned long threshold,
						void (*callback)(unsigned long))
{
	struct low_mem_threshold_ary *new;
	unsigned long free;
	int i, size, ret = 0;

	mutex_lock(&thresholds_lock);

	free = _usable_pages(); /* _free_pages(); */

	if (thresholds.primary)
		low_mem_notify_threshold(0);

	size = thresholds.primary ? thresholds.primary->size + 1 : 1;

	new = kmalloc(sizeof(*new) + size * sizeof(struct low_mem_threshold),
			GFP_KERNEL);
	if (!new) {
		ret = -ENOMEM;
		goto unlock;
	}
	new->size = size;

	if (thresholds.primary) {
		memcpy(new->entries, thresholds.primary->entries, (size - 1) *
				sizeof(struct low_mem_threshold));
	}

	new->entries[size - 1].eventfd = eventfd;
	new->entries[size - 1].threshold = threshold;
	new->entries[size - 1].k_callback = callback;

	sort(new->entries, size, sizeof(struct low_mem_threshold),
			compare_thresholds, NULL);
	#ifdef DEBUG
	for (i = 0; i < size; i++)
		dprintk("[%d] threshold : %ld\n", i, new->entries[i].threshold);
	#endif

	/*
	 * It should be cleared because the threshold corresponding
	 * to the index pointed to by the previous threshold may not
	 * be valid at this time.
	 */
	new->prev_threshold = -1;
	new->current_threshold = -1;

	for (i = 0; i < size; i++) {
		if (new->entries[i].threshold < free)
			++new->current_threshold;
	}
	dprintk("new current threshold ==> %d\n", new->current_threshold);

	kfree(thresholds.spare);
	thresholds.spare = thresholds.primary;

	rcu_assign_pointer(thresholds.primary, new);

	synchronize_rcu();

unlock:
	mutex_unlock(&thresholds_lock);
	return ret;
}

static void low_mem_unregister_event(struct eventfd_ctx *eventfd)
{
	struct low_mem_threshold_ary *new;
	unsigned long free;
	int i, j, size;

	mutex_lock(&thresholds_lock);

	free = _usable_pages(); /* _free_pages(); */

	size = 0;
	for (i=0; i < thresholds.primary->size; i++) {
		if (thresholds.primary->entries[i].eventfd != eventfd)
			size++;
	}

	if (thresholds.primary->size == size)
		goto unlock;

	new = kmalloc(sizeof(*new) + size * sizeof(struct low_mem_threshold),
			GFP_KERNEL);
	if (!new) {
		goto unlock;
	}
	new->size = size;

	/*
	 * It should be cleared because the threshold corresponding
	 * to the index pointed to by the previous threshold may not
	 * be valid at this time.
	 */
	new->prev_threshold = -1;
	new->current_threshold = -1;

	for (i = 0, j = 0; i < thresholds.primary->size; i++) {
		if (thresholds.primary->entries[i].eventfd == eventfd)
			continue;

		new->entries[j] = thresholds.primary->entries[i];
		if (new->entries[j].threshold <= free)
			++new->current_threshold;

		j++;
	}

	#ifdef DEBUG
	for (i = 0; i < size; i++)
		dprintk("[%d] threshold : %ld\n", i, new->entries[i].threshold);
	#endif

	kfree(thresholds.spare);
	thresholds.spare = thresholds.primary;

	rcu_assign_pointer(thresholds.primary, new);

	synchronize_rcu();
unlock:
	mutex_unlock(&thresholds_lock);
}

static int check_duplicate_event(struct eventfd_ctx *eventfd)
{
	int i;
	mutex_lock(&thresholds_lock);
	for (i=0; i < thresholds.primary->size; i++) {
		if (thresholds.primary->entries[i].eventfd == eventfd) {
			dprintk("eventfd(%p) is duplicated !!\n", eventfd);
			mutex_unlock(&thresholds_lock);
			return 1;
		}
	}
	mutex_unlock(&thresholds_lock);
	return 0;
}

static int low_mem_reset_events(void)
{
	mutex_lock(&thresholds_lock);

	kfree(thresholds.primary);
	kfree(thresholds.spare);

	thresholds.primary = thresholds.spare = NULL;

	mutex_unlock(&thresholds_lock);

	return 0;
}

void low_mem_notify_set_freeze(unsigned long flag)
{
	atomic_set(&freeze, flag);
}
EXPORT_SYMBOL_GPL(low_mem_notify_set_freeze);

#ifdef CONFIG_SYSFS

#define LOW_MEM_ATTR_RO(_name)				      \
	static struct kobj_attribute low_mem_##_name##_attr = \
		__ATTR_RO(_name)

#ifndef __ATTR_WO
#define __ATTR_WO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = S_IWUSR },	\
	.store	= _name##_store,					\
}
#endif

#define LOW_MEM_ATTR_WO(_name)				      \
	static struct kobj_attribute low_mem_##_name##_attr = \
		__ATTR_WO(_name)

#define LOW_MEM_ATTR(_name)				      \
	static struct kobj_attribute low_mem_##_name##_attr = \
		__ATTR(_name, 0644, _name##_show, _name##_store)

static unsigned low_mem_margin_to_minfree(unsigned percent)
{
	return (percent * (total_pages)) / 100;
}

static ssize_t free_pages_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%ld\n", _free_pages());
}
LOW_MEM_ATTR_RO(free_pages);

static ssize_t usable_pages_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%ld\n", _usable_pages());
}
LOW_MEM_ATTR_RO(usable_pages);

static ssize_t thresholds_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct low_mem_threshold_ary *t;
	ssize_t count = 0;
	int i;

	rcu_read_lock();
	t = rcu_dereference(thresholds.primary);
	if (!t)
		goto unlock;

	for (i = 0; i < t->size; i++) {
		if (i == t->current_threshold)
			count += sprintf(&buf[count], "*");
		count += sprintf(&buf[count], "%ld ", t->entries[i].threshold);
	}
	count += sprintf(&buf[count], "\n");

unlock:
	rcu_read_unlock();
	return count;
}
LOW_MEM_ATTR_RO(thresholds);

static ssize_t level_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct low_mem_threshold_ary *t;
	ssize_t count = 0;

	rcu_read_lock();
	t = rcu_dereference(thresholds.primary);
	if (!t)
		goto unlock;

	count = sprintf(buf, "%u\n", t->current_threshold);
unlock:
	rcu_read_unlock();
	return count;
}
LOW_MEM_ATTR_RO(level);

static ssize_t event_ctrl_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct low_mem_threshold_ary *t;
	ssize_t count = 0;

	rcu_read_lock();
	t = rcu_dereference(thresholds.primary);
	if (!t)
		goto unlock;

	count = sprintf(buf, "%u\n", t->size);

unlock:
	rcu_read_unlock();
	return count;
}

static ssize_t event_ctrl_store(struct kobject *kobj,
                                        struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct eventfd_ctx *eventfd = NULL;
	struct file *efile = NULL;
	int err, ret = 0;
	long input;
	unsigned int efd;
	unsigned long threshold;
	char *buffer, *endp;

	if(total_pages == 0)
		total_pages = totalram_pages + total_swap_pages;

	/* <event_fd> <threshold> */
	efd = simple_strtoul(buf, &endp, 10);
	if (*endp != ' ')
		return -EINVAL;
	buffer = endp + 1;

	err = kstrtol(buffer, 10, &input);
	if (err)
		return -EINVAL;

	efile = eventfd_fget(efd);
	if (IS_ERR(efile)) {
		ret = PTR_ERR(efile);
		goto fail;
	}

	eventfd = eventfd_ctx_fileget(efile);
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto fail;
	}

	dprintk("input = %ld, efd = %d\n", input, efd);
	if ((input < 0) && check_duplicate_event(eventfd)) {
		low_mem_unregister_event(eventfd);
		ret = count;
		goto out;
	}

	if (atomic_read(&ratio))
		threshold = low_mem_margin_to_minfree(input);
	else
		threshold = (input < 0) ? total_pages : input;

	ret = low_mem_register_event(eventfd, threshold, NULL);
	if (ret)
		goto fail;

	fput(efile);

	return count;

fail:

	if(eventfd && !IS_ERR(eventfd))
		eventfd_ctx_put(eventfd);
out:
	if (!IS_ERR_OR_NULL(efile))
		fput(efile);

	return ret;
}
LOW_MEM_ATTR(event_ctrl);

static ssize_t reset_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	/* reset thresholds */
	low_mem_reset_events();

	return count;
}
LOW_MEM_ATTR_WO(reset);

static ssize_t ratio_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	size_t count;
	count = sprintf(buf, "%d\n", atomic_read(&ratio));
	return count;
}

static ssize_t ratio_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long t;
	char *tmp;
	int ret;

	tmp = strstrip((char*)buf);
	if (strlen(tmp) == 0)
		return 0;

	ret = kstrtoul(tmp, 10, &t);
	if (ret)
		return -EINVAL;

	atomic_set(&ratio, (t > 0) ? 1 : 0);

	return count;
}
LOW_MEM_ATTR(ratio);

static ssize_t zramswap_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	size_t count;
	count = sprintf(buf, "%d\n", atomic_read(&zramswap));
	return count;
}

static ssize_t zramswap_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long t;
	char *tmp;
	int ret;

	tmp = strstrip((char*)buf);
	if (strlen(tmp) == 0)
		return 0;

	ret = kstrtoul(tmp, 10, &t);
	if (ret)
		return -EINVAL;

	atomic_set(&zramswap, (t > 0) ? 1 : 0);

	return count;
}
LOW_MEM_ATTR(zramswap);

static ssize_t force_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	if (atomic_read(&freeze))
		return count;

	low_mem_notify_threshold(1);
	return count;
}
LOW_MEM_ATTR_WO(force);

static ssize_t freeze_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	size_t count;
	count = sprintf(buf, "%d\n", atomic_read(&freeze));
	return count;
}

static ssize_t freeze_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long t;
	char *tmp;
	int ret;

	tmp = strstrip((char*)buf);
	if (strlen(tmp) == 0)
		return 0;

	ret = kstrtoul(tmp, 10, &t);
	if (ret)
		return -EINVAL;

	low_mem_notify_set_freeze((t > 0) ? 1 : 0);
	return count;
}
LOW_MEM_ATTR(freeze);

static ssize_t threshold_walking_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	size_t count;
	count = sprintf(buf, "%d\n", threshold_walking);
	return count;
}

static ssize_t threshold_walking_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long t;
	char *tmp;
	int ret;

	tmp = strstrip((char*)buf);
	if (strlen(tmp) == 0)
		return 0;

	ret = kstrtoul(tmp, 10, &t);
	if (ret)
		return -EINVAL;

	threshold_walking = t > 0 ? 1 : 0 ;
	return count;
}
LOW_MEM_ATTR(threshold_walking);

static ssize_t prevent_jittering_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	size_t count;
	count = sprintf(buf, "%d\n", prevent_jittering);
	return count;
}

static ssize_t prevent_jittering_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long t;
	char *tmp;
	int ret;

	tmp = strstrip((char*)buf);
	if (strlen(tmp) == 0)
		return 0;

	ret = kstrtoul(tmp, 10, &t);
	if (ret)
		return -EINVAL;

	prevent_jittering = t > 0 ? 1 : 0 ;
	return count;
}
LOW_MEM_ATTR(prevent_jittering);

static ssize_t usable_stat_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	unsigned long free = get_free_pages();
	unsigned long reserved = get_reserved_pages();
	unsigned long file = get_file_pages();
	unsigned long shmem = get_shmem_pages();
	unsigned long slab_reclaimable = get_slab_reclaimable_pages();
	unsigned long swap = get_swap_pages();
	unsigned long swapcache = get_swapcache_pages();
	unsigned long zramuse = get_zramswap_pages();
	unsigned long usable;
	ssize_t count = 0;

	usable = free + file + swap + slab_reclaimable - swapcache - zramuse - reserved - shmem;

	count  = sprintf(&buf[count], "usable pages :         %8lu\n", usable);
	count += sprintf(&buf[count], "(+) free :             %8lu\n", free);
	count += sprintf(&buf[count], "(+) file :             %8lu\n", file);
	count += sprintf(&buf[count], "(+) swap :             %8lu\n", swap);
	count += sprintf(&buf[count], "(+) slab_reclaimable : %8lu\n", slab_reclaimable);
	count += sprintf(&buf[count], "(-) swapcache :        %8lu\n", swapcache);
	count += sprintf(&buf[count], "(-) zramuse :          %8lu\n", zramuse);
	count += sprintf(&buf[count], "(-) totalreserved :    %8lu\n", reserved);
	count += sprintf(&buf[count], "(-) shmem:             %8lu\n", shmem);
	count += sprintf(&buf[count], "thresholds : ");
	count += thresholds_show(kobj, attr, &buf[count]);
	count += sprintf(&buf[count], "\n");

	return count;
}
LOW_MEM_ATTR_RO(usable_stat);

static ssize_t usable_raw_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	unsigned long free = get_free_pages();
	unsigned long reserved = get_reserved_pages();
	unsigned long file = get_file_pages();
	unsigned long shmem = get_shmem_pages();
	unsigned long slab_reclaimable = get_slab_reclaimable_pages();
	unsigned long swap = get_swap_pages();
	unsigned long swapcache = get_swapcache_pages();
	unsigned long zramuse = get_zramswap_pages();
	unsigned long usable;

	usable = free + file + swap + slab_reclaimable - swapcache - zramuse - reserved - shmem;
	return sprintf(buf, "%ld %ld %ld %ld %ld %ld %ld %ld %ld\n",
			usable, free, file, swap, slab_reclaimable, swapcache, zramuse, reserved, shmem);
}
LOW_MEM_ATTR_RO(usable_raw);

static struct attribute *low_mem_attrs[] = {
	&low_mem_free_pages_attr.attr,
	&low_mem_usable_pages_attr.attr,
	&low_mem_level_attr.attr,
	&low_mem_thresholds_attr.attr,
	&low_mem_event_ctrl_attr.attr,
	&low_mem_reset_attr.attr,
	&low_mem_ratio_attr.attr,
	&low_mem_zramswap_attr.attr,
	&low_mem_force_attr.attr,
	&low_mem_freeze_attr.attr,
	&low_mem_usable_stat_attr.attr,
	&low_mem_usable_raw_attr.attr,
	&low_mem_threshold_walking_attr.attr,
	&low_mem_prevent_jittering_attr.attr,
	NULL,
};

static struct attribute_group low_mem_attr_group = {
	.attrs = low_mem_attrs,
	.name = "low_mem_notify",
};

static int __init low_mem_init(void)
{
	int err = sysfs_create_group(mm_kobj, &low_mem_attr_group);
	if (err)
		printk(KERN_ERR "low_mem: register sysfs failed\n");

	atomic_set(&ratio, DEFAULT_RATIO);
	atomic_set(&zramswap, 0);
	atomic_set(&freeze, 0);

	memset(&thresholds, 0, sizeof(struct low_mem_thresholds));
	mutex_init(&thresholds_lock);

	reg_basic_callback();

	return err;
}
module_init(low_mem_init)

#endif
