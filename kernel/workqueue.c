// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/workqueue.c - generic async execution with shared worker pool
 *
 * Copyright (C) 2002       Ingo Molnar
 *
 *   Derived from the taskqueue/keventd code by:
 *     David Woodhouse <dwmw2@infradead.org>
 *     Andrew Morton
 *     Kai Petzke <wpp@marie.physik.tu-berlin.de>
 *     Theodore Ts'o <tytso@mit.edu>
 *
 * Made to use alloc_percpu by Christoph Lameter.
 *
 * Copyright (C) 2010       SUSE Linux Products GmbH
 * Copyright (C) 2010       Tejun Heo <tj@kernel.org>
 *
 * This is the generic async execution mechanism.  Work items as are
 * executed in process context.  The worker pool is shared and
 * automatically managed.  There are two worker pools for each CPU (one for
 * normal work items and the other for high priority ones) and some extra
 * pools for workqueues which are not bound to any specific CPU - the
 * number of these backing pools is dynamic.
 *
 * Please read Documentation/core-api/workqueue.rst for details.
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/hardirq.h>
#include <linux/mempolicy.h>
#include <linux/freezer.h>
#include <linux/debug_locks.h>
#include <linux/lockdep.h>
#include <linux/idr.h>
#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/rculist.h>
#include <linux/nodemask.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/sched/isolation.h>
#include <linux/sched/debug.h>
#include <linux/nmi.h>
#include <linux/kvm_para.h>
#include <linux/delay.h>

#include "workqueue_internal.h"
#include "workqueue.h"

enum {
    /*
     * worker_pool flags
     *
     * A bound pool is either associated or disassociated with its CPU.
     * While associated (!DISASSOCIATED), all workers are bound to the
     * CPU and none has %WORKER_UNBOUND set and concurrency management
     * is in effect.
     *
     * While DISASSOCIATED, the cpu may be offline and all workers have
     * %WORKER_UNBOUND set and concurrency management disabled, and may
     * be executing on any CPU.  The pool behaves as an unbound one.
     *
     * Note that DISASSOCIATED should be flipped only while holding
     * wq_pool_attach_mutex to avoid changing binding state while
     * worker_attach_to_pool() is in progress.
     */
    POOL_MANAGER_ACTIVE = 1 << 0,   /* being managed */
    POOL_DISASSOCIATED  = 1 << 2,   /* cpu can't serve workers */

    /* worker flags */
    WORKER_DIE      = 1 << 1,   /* die die die */
    WORKER_IDLE     = 1 << 2,   /* is idle */
    WORKER_PREP     = 1 << 3,   /* preparing to run works */
    WORKER_CPU_INTENSIVE    = 1 << 6,   /* cpu intensive */
    WORKER_UNBOUND      = 1 << 7,   /* worker is unbound */
    WORKER_REBOUND      = 1 << 8,   /* worker was rebound */

    WORKER_NOT_RUNNING  = WORKER_PREP | WORKER_CPU_INTENSIVE |
                  WORKER_UNBOUND | WORKER_REBOUND,

    NR_STD_WORKER_POOLS = 2,        /* # standard pools per cpu */

    UNBOUND_POOL_HASH_ORDER = 6,        /* hashed by pool->attrs */
    BUSY_WORKER_HASH_ORDER  = 6,        /* 64 pointers */

    MAX_IDLE_WORKERS_RATIO  = 4,        /* 1/4 of busy can be idle */
    IDLE_WORKER_TIMEOUT = 300 * HZ, /* keep idle ones for 5 mins */

    MAYDAY_INITIAL_TIMEOUT  = HZ / 100 >= 2 ? HZ / 100 : 2,
                        /* call for help after 10ms
                           (min two ticks) */
    MAYDAY_INTERVAL     = HZ / 10,  /* and then every 100ms */
    CREATE_COOLDOWN     = HZ,       /* time to breath after fail */

    /*
     * Rescue workers are used only on emergencies and shared by
     * all cpus.  Give MIN_NICE.
     */
    RESCUER_NICE_LEVEL  = MIN_NICE,
    HIGHPRI_NICE_LEVEL  = MIN_NICE,

    WQ_NAME_LEN     = 24,
};

struct worker_pool {
    raw_spinlock_t      lock;       /* the pool lock */
    int         cpu;        /* I: the associated cpu */
    int         node;       /* I: the associated node ID */
    int         id;     /* I: pool ID */
    unsigned int        flags;      /* L: flags */

    unsigned long       watchdog_ts;    /* L: watchdog timestamp */
    bool            cpu_stall;  /* WD: stalled cpu bound pool */

    /*
     * The counter is incremented in a process context on the associated CPU
     * w/ preemption disabled, and decremented or reset in the same context
     * but w/ pool->lock held. The readers grab pool->lock and are
     * guaranteed to see if the counter reached zero.
     */
    int         nr_running;

    struct list_head    worklist;   /* L: list of pending works */

    int         nr_workers; /* L: total number of workers */
    int         nr_idle;    /* L: currently idle workers */

    struct list_head    idle_list;  /* L: list of idle workers */
    struct timer_list   idle_timer; /* L: worker idle timeout */
    struct work_struct      idle_cull_work; /* L: worker idle cleanup */

    struct timer_list   mayday_timer;     /* L: SOS timer for workers */

    /* a workers is either on busy_hash or idle_list, or the manager */
    DECLARE_HASHTABLE(busy_hash, BUSY_WORKER_HASH_ORDER);
                        /* L: hash of busy workers */

    struct worker       *manager;   /* L: purely informational */
    struct list_head    workers;    /* A: attached workers */
    struct list_head        dying_workers;  /* A: workers about to die */
    struct completion   *detach_completion; /* all workers detached */

    struct ida      worker_ida; /* worker IDs for task name */

    struct workqueue_attrs  *attrs;     /* I: worker attributes */
    struct hlist_node   hash_node;  /* PL: unbound_pool_hash node */
    int         refcnt;     /* PL: refcnt for unbound pools */

    /*
     * Destruction of pool is RCU protected to allow dereferences
     * from get_work_pool().
     */
    struct rcu_head     rcu;
};

/*
 * Per-pool_workqueue statistics. These can be monitored using
 * tools/workqueue/wq_monitor.py.
 */
enum pool_workqueue_stats {
    PWQ_STAT_STARTED,   /* work items started execution */
    PWQ_STAT_COMPLETED, /* work items completed execution */
    PWQ_STAT_CPU_TIME,  /* total CPU time consumed */
    PWQ_STAT_CPU_INTENSIVE, /* wq_cpu_intensive_thresh_us violations */
    PWQ_STAT_CM_WAKEUP, /* concurrency-management worker wakeups */
    PWQ_STAT_REPATRIATED,   /* unbound workers brought back into scope */
    PWQ_STAT_MAYDAY,    /* maydays to rescuer */
    PWQ_STAT_RESCUED,   /* linked work items executed by rescuer */

    PWQ_NR_STATS,
};

/*
 * The per-pool workqueue.  While queued, the lower WORK_STRUCT_FLAG_BITS
 * of work_struct->data are used for flags and the remaining high bits
 * point to the pwq; thus, pwqs need to be aligned at two's power of the
 * number of flag bits.
 */
struct pool_workqueue {
    struct worker_pool  *pool;      /* I: the associated pool */
    struct workqueue_struct *wq;        /* I: the owning workqueue */
    int         work_color; /* L: current color */
    int         flush_color;    /* L: flushing color */
    int         refcnt;     /* L: reference count */
    int         nr_in_flight[WORK_NR_COLORS];
                        /* L: nr of in_flight works */

    /*
     * nr_active management and WORK_STRUCT_INACTIVE:
     *
     * When pwq->nr_active >= max_active, new work item is queued to
     * pwq->inactive_works instead of pool->worklist and marked with
     * WORK_STRUCT_INACTIVE.
     *
     * All work items marked with WORK_STRUCT_INACTIVE do not participate
     * in pwq->nr_active and all work items in pwq->inactive_works are
     * marked with WORK_STRUCT_INACTIVE.  But not all WORK_STRUCT_INACTIVE
     * work items are in pwq->inactive_works.  Some of them are ready to
     * run in pool->worklist or worker->scheduled.  Those work itmes are
     * only struct wq_barrier which is used for flush_work() and should
     * not participate in pwq->nr_active.  For non-barrier work item, it
     * is marked with WORK_STRUCT_INACTIVE iff it is in pwq->inactive_works.
     */
    int         nr_active;  /* L: nr of active works */
    int         max_active; /* L: max active works */
    struct list_head    inactive_works; /* L: inactive works */
    struct list_head    pwqs_node;  /* WR: node on wq->pwqs */
    struct list_head    mayday_node;    /* MD: node on wq->maydays */

    u64         stats[PWQ_NR_STATS];

    /*
     * Release of unbound pwq is punted to a kthread_worker. See put_pwq()
     * and pwq_release_workfn() for details. pool_workqueue itself is also
     * RCU protected so that the first pwq can be determined without
     * grabbing wq->mutex.
     */
    struct kthread_work release_work;
    struct rcu_head     rcu;
} __aligned(1 << WORK_STRUCT_FLAG_BITS);

/*
 * The externally visible workqueue.  It relays the issued work items to
 * the appropriate worker_pool through its pool_workqueues.
 */
struct workqueue_struct {
    struct list_head    pwqs;       /* WR: all pwqs of this wq */
    struct list_head    list;       /* PR: list of all workqueues */

    struct mutex        mutex;      /* protects this wq */
    int         work_color; /* WQ: current work color */
    int         flush_color;    /* WQ: current flush color */
    atomic_t        nr_pwqs_to_flush; /* flush in progress */
    struct wq_flusher   *first_flusher; /* WQ: first flusher */
    struct list_head    flusher_queue;  /* WQ: flush waiters */
    struct list_head    flusher_overflow; /* WQ: flush overflow list */

    struct list_head    maydays;    /* MD: pwqs requesting rescue */
    struct worker       *rescuer;   /* MD: rescue worker */

    int         nr_drainers;    /* WQ: drain in progress */
    int         saved_max_active; /* WQ: saved pwq max_active */

    struct workqueue_attrs  *unbound_attrs; /* PW: only for unbound wqs */
    struct pool_workqueue   *dfl_pwq;   /* PW: only for unbound wqs */

#ifdef CONFIG_SYSFS
    struct wq_device    *wq_dev;    /* I: for sysfs interface */
#endif
#ifdef CONFIG_LOCKDEP
    char            *lock_name;
    struct lock_class_key   key;
    struct lockdep_map  lockdep_map;
#endif
    char            name[WQ_NAME_LEN]; /* I: workqueue name */

    /*
     * Destruction of workqueue_struct is RCU protected to allow walking
     * the workqueues list without grabbing wq_pool_mutex.
     * This is used to dump all workqueues from sysrq.
     */
    struct rcu_head     rcu;

    /* hot fields used during command issue, aligned to cacheline */
    unsigned int        flags ____cacheline_aligned; /* WQ: WQ_* flags */
    struct pool_workqueue __percpu __rcu **cpu_pwq; /* I: per-cpu pwqs */
};

/*
 * Test whether @work is being queued from another work executing on the
 * same workqueue.
 */
static bool my_is_chained_work(struct workqueue_struct *wq)
{
    struct worker *worker;

    worker = current_wq_worker();
    /*
     * Return %true iff I'm a worker executing a work item on @wq.  If
     * I'm @worker, it's safe to dereference it without locking.
     */
    return worker && worker->current_pwq->wq == wq;
}

/*
 * Local execution of unbound work items is no longer guaranteed.  The
 * following always forces round-robin CPU selection on unbound work items
 * to uncover usages which depend on it.
 */
#ifdef CONFIG_DEBUG_WQ_FORCE_RR_CPU
static bool wq_debug_force_rr_cpu = true;
#else
static bool wq_debug_force_rr_cpu = false;
#endif
module_param_named(debug_force_rr_cpu, wq_debug_force_rr_cpu, bool, 0644);

/* PL&A: allowable cpus for unbound wqs and work items */
static cpumask_var_t wq_unbound_cpumask;

/* CPU where unbound work was last round robin scheduled from this CPU */
static DEFINE_PER_CPU(int, wq_rr_cpu_last);

/*
 * When queueing an unbound work item to a wq, prefer local CPU if allowed
 * by wq_unbound_cpumask.  Otherwise, round robin among the allowed ones to
 * avoid perturbing sensitive tasks.
 */
static int my_wq_select_unbound_cpu(int cpu)
{
    int new_cpu;

    if (likely(!wq_debug_force_rr_cpu)) {
        if (cpumask_test_cpu(cpu, wq_unbound_cpumask))
            return cpu;
    } else {
        pr_warn_once("workqueue: round-robin CPU selection forced, expect performance impact\n");
    }

    new_cpu = __this_cpu_read(wq_rr_cpu_last);
    new_cpu = cpumask_next_and(new_cpu, wq_unbound_cpumask, cpu_online_mask);
    if (unlikely(new_cpu >= nr_cpu_ids)) {
        new_cpu = cpumask_first_and(wq_unbound_cpumask, cpu_online_mask);
        if (unlikely(new_cpu >= nr_cpu_ids))
            return cpu;
    }
    __this_cpu_write(wq_rr_cpu_last, new_cpu);

    return new_cpu;
}

static DEFINE_MUTEX(wq_pool_mutex); /* protects pools and workqueues list */

#define my_assert_rcu_or_pool_mutex()                  \
    RCU_LOCKDEP_WARN(!rcu_read_lock_held() &&           \
             !lockdep_is_held(&wq_pool_mutex),      \
             "RCU or wq_pool_mutex should be held")

static inline struct pool_workqueue *my_work_struct_pwq(unsigned long data)
{
    return (struct pool_workqueue *)(data & WORK_STRUCT_WQ_DATA_MASK);
}

static DEFINE_IDR(worker_pool_idr); /* PR: idr of all pools */

/**
 * get_work_pool - return the worker_pool a given work was associated with
 * @work: the work item of interest
 *
 * Pools are created and destroyed under wq_pool_mutex, and allows read
 * access under RCU read lock.  As such, this function should be
 * called under wq_pool_mutex or inside of a rcu_read_lock() region.
 *
 * All fields of the returned pool are accessible as long as the above
 * mentioned locking is in effect.  If the returned pool needs to be used
 * beyond the critical section, the caller is responsible for ensuring the
 * returned pool is and stays online.
 *
 * Return: The worker_pool @work was last associated with.  %NULL if none.
 */
static struct worker_pool *my_get_work_pool(struct work_struct *work)
{
    unsigned long data = atomic_long_read(&work->data);
    int pool_id;

    my_assert_rcu_or_pool_mutex();

    if (data & WORK_STRUCT_PWQ)
        return my_work_struct_pwq(data)->pool;

    pool_id = data >> WORK_OFFQ_POOL_SHIFT;
    if (pool_id == WORK_OFFQ_POOL_NONE)
        return NULL;

    return idr_find(&worker_pool_idr, pool_id);
}

/**
 * find_worker_executing_work - find worker which is executing a work
 * @pool: pool of interest
 * @work: work to find worker for
 *
 * Find a worker which is executing @work on @pool by searching
 * @pool->busy_hash which is keyed by the address of @work.  For a worker
 * to match, its current execution should match the address of @work and
 * its work function.  This is to avoid unwanted dependency between
 * unrelated work executions through a work item being recycled while still
 * being executed.
 *
 * This is a bit tricky.  A work item may be freed once its execution
 * starts and nothing prevents the freed area from being recycled for
 * another work item.  If the same work item address ends up being reused
 * before the original execution finishes, workqueue will identify the
 * recycled work item as currently executing and make it wait until the
 * current execution finishes, introducing an unwanted dependency.
 *
 * This function checks the work item address and work function to avoid
 * false positives.  Note that this isn't complete as one may construct a
 * work function which can introduce dependency onto itself through a
 * recycled work item.  Well, if somebody wants to shoot oneself in the
 * foot that badly, there's only so much we can do, and if such deadlock
 * actually occurs, it should be easy to locate the culprit work function.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock).
 *
 * Return:
 * Pointer to worker which is executing @work if found, %NULL
 * otherwise.
 */
static struct worker *find_worker_executing_work(struct worker_pool *pool,
                         struct work_struct *work)
{
    struct worker *worker;

    hash_for_each_possible(pool->busy_hash, worker, hentry,
                   (unsigned long)work)
        if (worker->current_work == work &&
            worker->current_func == work->func)
            return worker;

    return NULL;
}

static unsigned int my_work_color_to_flags(int color)
{
    return color << WORK_STRUCT_COLOR_SHIFT;
}

#ifdef CONFIG_DEBUG_OBJECTS_WORK
static inline void my_debug_work_activate(struct work_struct *work)
{
    debug_object_activate(work, &work_debug_descr);
}
#else
static inline void my_debug_work_activate(struct work_struct *work) { }
#endif

/*
 * While queued, %WORK_STRUCT_PWQ is set and non flag bits of a work's data
 * contain the pointer to the queued pwq.  Once execution starts, the flag
 * is cleared and the high bits contain OFFQ flags and pool ID.
 *
 * set_work_pwq(), set_work_pool_and_clear_pending(), mark_work_canceling()
 * and clear_work_data() can be used to set the pwq, pool or clear
 * work->data.  These functions should only be called while the work is
 * owned - ie. while the PENDING bit is set.
 *
 * get_work_pool() and get_work_pwq() can be used to obtain the pool or pwq
 * corresponding to a work.  Pool is available once the work has been
 * queued anywhere after initialization until it is sync canceled.  pwq is
 * available only while the work item is queued.
 *
 * %WORK_OFFQ_CANCELING is used to mark a work item which is being
 * canceled.  While being canceled, a work item may have its PENDING set
 * but stay off timer and worklist for arbitrarily long and nobody should
 * try to steal the PENDING bit.
 */
static inline void my_set_work_data(struct work_struct *work, unsigned long data,
                 unsigned long flags)
{
    WARN_ON_ONCE(!work_pending(work));
    atomic_long_set(&work->data, data | flags | work_static(work));
}

static void my_set_work_pwq(struct work_struct *work, struct pool_workqueue *pwq,
             unsigned long extra_flags)
{
    my_set_work_data(work, (unsigned long)pwq,
              WORK_STRUCT_PENDING | WORK_STRUCT_PWQ | extra_flags);
}

/**
 * get_pwq - get an extra reference on the specified pool_workqueue
 * @pwq: pool_workqueue to get
 *
 * Obtain an extra reference on @pwq.  The caller should guarantee that
 * @pwq has positive refcnt and be holding the matching pool->lock.
 */
static void my_get_pwq(struct pool_workqueue *pwq)
{
    lockdep_assert_held(&pwq->pool->lock);
    WARN_ON_ONCE(pwq->refcnt <= 0);
    pwq->refcnt++;
}

/**
 * insert_work - insert a work into a pool
 * @pwq: pwq @work belongs to
 * @work: work to insert
 * @head: insertion point
 * @extra_flags: extra WORK_STRUCT_* flags to set
 *
 * Insert @work which belongs to @pwq after @head.  @extra_flags is or'd to
 * work_struct flags.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock).
 */
static void my_insert_work(struct pool_workqueue *pwq, struct work_struct *work,
            struct list_head *head, unsigned int extra_flags)
{
    my_debug_work_activate(work);

    /* record the work call stack in order to print it in KASAN reports */
    kasan_record_aux_stack_noalloc(work);

    /* we own @work, set data and link */
    my_set_work_pwq(work, pwq, extra_flags);
    list_add_tail(&work->entry, head);
    my_get_pwq(pwq);
}

/* Return the first idle worker.  Called with pool->lock held. */
static struct worker *my_first_idle_worker(struct worker_pool *pool)
{
    if (unlikely(list_empty(&pool->idle_list)))
        return NULL;

    return list_first_entry(&pool->idle_list, struct worker, entry);
}

/*
 * Policy functions.  These define the policies on how the global worker
 * pools are managed.  Unless noted otherwise, these functions assume that
 * they're being called with pool->lock held.
 */

/*
 * Need to wake up a worker?  Called from anything but currently
 * running workers.
 *
 * Note that, because unbound workers never contribute to nr_running, this
 * function will always return %true for unbound pools as long as the
 * worklist isn't empty.
 */
static bool need_more_worker(struct worker_pool *pool)
{
    return !list_empty(&pool->worklist) && !pool->nr_running;
}


static struct pool_workqueue *get_work_pwq(struct work_struct *work)
{
    unsigned long data = atomic_long_read(&work->data);

    if (data & WORK_STRUCT_PWQ)
        return my_work_struct_pwq(data);
    else
        return NULL;
}

/**
 * kick_pool - wake up an idle worker if necessary
 * @pool: pool to kick
 *
 * @pool may have pending work items. Wake up worker if necessary. Returns
 * whether a worker was woken up.
 */
static bool my_kick_pool(struct worker_pool *pool)
{
    struct worker *worker = my_first_idle_worker(pool);
    struct task_struct *p;

    lockdep_assert_held(&pool->lock);

    if (!need_more_worker(pool) || !worker)
        return false;

    p = worker->task;

#ifdef CONFIG_SMP
    /*
     * Idle @worker is about to execute @work and waking up provides an
     * opportunity to migrate @worker at a lower cost by setting the task's
     * wake_cpu field. Let's see if we want to move @worker to improve
     * execution locality.
     *
     * We're waking the worker that went idle the latest and there's some
     * chance that @worker is marked idle but hasn't gone off CPU yet. If
     * so, setting the wake_cpu won't do anything. As this is a best-effort
     * optimization and the race window is narrow, let's leave as-is for
     * now. If this becomes pronounced, we can skip over workers which are
     * still on cpu when picking an idle worker.
     *
     * If @pool has non-strict affinity, @worker might have ended up outside
     * its affinity scope. Repatriate.
     */
    if (!pool->attrs->affn_strict &&
        !cpumask_test_cpu(p->wake_cpu, pool->attrs->__pod_cpumask)) {
        struct work_struct *work = list_first_entry(&pool->worklist,
                        struct work_struct, entry);
        p->wake_cpu = cpumask_any_distribute(pool->attrs->__pod_cpumask);
        get_work_pwq(work)->stats[PWQ_STAT_REPATRIATED]++;
    }
#endif
    wake_up_process(p);
    return true;
}

static void __my_queue_work(int cpu, struct workqueue_struct *wq,
             struct work_struct *work)
{
    struct pool_workqueue *pwq;
    struct worker_pool *last_pool, *pool;
    unsigned int work_flags;
    unsigned int req_cpu = cpu;

    /*
     * While a work item is PENDING && off queue, a task trying to
     * steal the PENDING will busy-loop waiting for it to either get
     * queued or lose PENDING.  Grabbing PENDING and queueing should
     * happen with IRQ disabled.
     */
    lockdep_assert_irqs_disabled();


    /*
     * For a draining wq, only works from the same workqueue are
     * allowed. The __WQ_DESTROYING helps to spot the issue that
     * queues a new work item to a wq after destroy_workqueue(wq).
     */
    if (unlikely(wq->flags & (__WQ_DESTROYING | __WQ_DRAINING) &&
             WARN_ON_ONCE(!my_is_chained_work(wq))))
        return;
    rcu_read_lock();
retry:
    /* pwq which will be used unless @work is executing elsewhere */
    if (req_cpu == WORK_CPU_UNBOUND) {
        if (wq->flags & WQ_UNBOUND)
            cpu = my_wq_select_unbound_cpu(raw_smp_processor_id());
        else
            cpu = raw_smp_processor_id();
    }

    pwq = rcu_dereference(*per_cpu_ptr(wq->cpu_pwq, cpu));
    pool = pwq->pool;

    /*
     * If @work was previously on a different pool, it might still be
     * running there, in which case the work needs to be queued on that
     * pool to guarantee non-reentrancy.
     */
    last_pool = my_get_work_pool(work);
    if (last_pool && last_pool != pool) {
        struct worker *worker;

        raw_spin_lock(&last_pool->lock);

        worker = find_worker_executing_work(last_pool, work);

        if (worker && worker->current_pwq->wq == wq) {
            pwq = worker->current_pwq;
            pool = pwq->pool;
            WARN_ON_ONCE(pool != last_pool);
        } else {
            /* meh... not running there, queue here */
            raw_spin_unlock(&last_pool->lock);
            raw_spin_lock(&pool->lock);
        }
    } else {
        raw_spin_lock(&pool->lock);
    }

    /*
     * pwq is determined and locked. For unbound pools, we could have raced
     * with pwq release and it could already be dead. If its refcnt is zero,
     * repeat pwq selection. Note that unbound pwqs never die without
     * another pwq replacing it in cpu_pwq or while work items are executing
     * on it, so the retrying is guaranteed to make forward-progress.
     */
    if (unlikely(!pwq->refcnt)) {
        if (wq->flags & WQ_UNBOUND) {
            raw_spin_unlock(&pool->lock);
            cpu_relax();
            goto retry;
        }
        /* oops */
        WARN_ONCE(true, "workqueue: per-cpu pwq for %s on cpu%d has 0 refcnt",
              wq->name, cpu);
    }

	/* pwq determined, queue */
    // trace_workqueue_queue_work(req_cpu, pwq, work);
    
	if (WARN_ON(!list_empty(&work->entry)))
        goto out;

    pwq->nr_in_flight[pwq->work_color]++;
    work_flags = my_work_color_to_flags(pwq->work_color);

    if (likely(pwq->nr_active < pwq->max_active)) {
        if (list_empty(&pool->worklist))
            pool->watchdog_ts = jiffies;

		// trace_workqueue_activate_work(work);
        pwq->nr_active++;
        my_insert_work(pwq, work, &pool->worklist, work_flags);
        my_kick_pool(pool);
    } else {
        work_flags |= WORK_STRUCT_INACTIVE;
        my_insert_work(pwq, work, &pwq->inactive_works, work_flags);
    }

out:
    raw_spin_unlock(&pool->lock);
    rcu_read_unlock();
}

static void __my_queue_delayed_work(int cpu, struct workqueue_struct *wq,
                struct delayed_work *dwork, unsigned long delay)
{
    struct timer_list *timer = &dwork->timer;
    struct work_struct *work = &dwork->work;

    WARN_ON_ONCE(!wq);
    WARN_ON_ONCE(timer->function != delayed_work_timer_fn);
    WARN_ON_ONCE(timer_pending(timer));
    WARN_ON_ONCE(!list_empty(&work->entry));

    /*
     * If @delay is 0, queue @dwork->work immediately.  This is for
     * both optimization and correctness.  The earliest @timer can
     * expire is on the closest next tick and delayed_work users depend
     * on that there's no such delay when @delay is 0.
     */
    if (!delay) {
        __my_queue_work(cpu, wq, &dwork->work);
        return;
    }

    dwork->wq = wq;
    dwork->cpu = cpu;
    timer->expires = jiffies + delay;

    if (unlikely(cpu != WORK_CPU_UNBOUND))
        add_timer_on(timer, cpu);
    else
        add_timer(timer);
}

/**
 * queue_delayed_work_on - queue work on specific CPU after delay
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Return: %false if @work was already on a queue, %true otherwise.  If
 * @delay is zero and @dwork is idle, it will be scheduled for immediate
 * execution.
 */
bool my_queue_delayed_work_on(int cpu, struct workqueue_struct *wq,
               struct delayed_work *dwork, unsigned long delay)
{
    struct work_struct *work = &dwork->work;
    bool ret = false;
    unsigned long flags;

    /* read the comment in __queue_work() */
    local_irq_save(flags);

    if (!test_and_set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))) {
        __my_queue_delayed_work(cpu, wq, dwork, delay);
        ret = true;
    }

    local_irq_restore(flags);
    return ret;
}
