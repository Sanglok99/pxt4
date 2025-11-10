// SPDX-License-Identifier: GPL-2.0-only

#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/rbtree.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#include <linux/blk-cgroup.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/device.h>
#include <trace/events/writeback.h>
#include "internal.h"
#include "backing-dev.h"
#include "../kernel/workqueue.h"

extern struct workqueue_struct *bdi_wq;

/**
 * queue_delayed_work - queue work on a workqueue after delay
 * @wq: workqueue to use
 * @dwork: delayable work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Equivalent to queue_delayed_work_on() but tries to use the local CPU.
 */
static inline bool my_queue_delayed_work(struct workqueue_struct *wq,
                      struct delayed_work *dwork,
                      unsigned long delay)
{
    printk("[%s]: WORK_CPU_UNBOUND= %d\n", __func__, WORK_CPU_UNBOUND); // test code
    return my_queue_delayed_work_on(WORK_CPU_UNBOUND, wq, dwork, delay);
}

/*
 * This function is used when the first inode for this wb is marked dirty. It
 * wakes-up the corresponding bdi thread which should then take care of the
 * periodic background write-out of dirty inodes. Since the write-out would
 * starts only 'dirty_writeback_interval' centisecs from now anyway, we just
 * set up a timer which wakes the bdi thread up later.
 *
 * Note, we wouldn't bother setting up the timer, but this function is on the
 * fast-path (used by '__mark_inode_dirty()'), so we save few context switches
 * by delaying the wake-up.
 *
 * We have to be careful not to postpone flush work if it is scheduled for
 * earlier. Thus we use queue_delayed_work().
 */
void my_wb_wakeup_delayed(struct bdi_writeback *wb)
{
    unsigned long timeout;

    timeout = msecs_to_jiffies(dirty_writeback_interval * 10);

	printk("[%s]: timeout= %lu\n", __func__, timeout); // test code 

    spin_lock_irq(&wb->work_lock);
    if (test_bit(WB_registered, &wb->state))
        my_queue_delayed_work(bdi_wq, &wb->dwork, timeout);
    spin_unlock_irq(&wb->work_lock);
}
