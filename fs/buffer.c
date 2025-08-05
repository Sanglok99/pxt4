#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/hash.h>
#include <linux/suspend.h>
#include <linux/buffer_head.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/bio.h>
#include <linux/cpu.h>
#include <linux/bitops.h>
#include <linux/mpage.h>
#include <linux/bit_spinlock.h>
#include <linux/pagevec.h>
#include <linux/sched/mm.h>
#include <trace/events/block.h>
#include <linux/fscrypt.h>
#include <linux/fsverity.h>
#include <linux/sched/isolation.h>

// === header files in linux-6.6.8/include/linux/buffer_head.h ===
// start
#include <linux/types.h>
#include <linux/blk_types.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/pagemap.h>
#include <linux/wait.h>
#include <linux/atomic.h>
// end

#include "internal.h"
#include "buffer_head.h"

extern void check_irqs_on(void);
extern void link_dev_buffers(struct folio *folio, struct buffer_head *head);
extern sector_t folio_init_buffers(struct folio *folio, struct block_device *bdev, sector_t block, int size);

/*
 * Per-cpu buffer LRU implementation.  To reduce the cost of __find_get_block().
 * The bhs[] array is sorted - newest buffer is at bhs[0].  Buffers have their
 * refcount elevated by one when they're in an LRU.  A buffer can only appear
 * once in a particular CPU's LRU.  A single buffer can be present in multiple
 * CPU's LRUs at the same time.
 *
 * This is a transparent caching front-end to sb_bread(), sb_getblk() and
 * sb_find_get_block().
 *
 * The LRUs themselves only need locking against invalidate_bh_lrus.  We use
 * a local interrupt disable for that.
 */

#define BH_LRU_SIZE 16

struct bh_lru {
    struct buffer_head *bhs[BH_LRU_SIZE];
};

static DEFINE_PER_CPU(struct bh_lru, bh_lrus) = {{ NULL }};

#ifdef CONFIG_SMP
#define bh_lru_lock()   local_irq_disable()
#define bh_lru_unlock() local_irq_enable()
#else
#define bh_lru_lock()   preempt_disable()
#define bh_lru_unlock() preempt_enable()
#endif

/*
 * Look up th bh in this cpu's LRU.  If it's there, move it to the head.
 */
static struct buffer_head *
my_lookup_bh_lru(struct block_device *bdev, sector_t block, unsigned size)
{
    struct buffer_head *ret = NULL;
    unsigned int i;

    check_irqs_on();
    bh_lru_lock();
    if (cpu_is_isolated(smp_processor_id())) {
        bh_lru_unlock();
        return NULL;
    }
    for (i = 0; i < BH_LRU_SIZE; i++) {
        struct buffer_head *bh = __this_cpu_read(bh_lrus.bhs[i]);

        if (bh && bh->b_blocknr == block && bh->b_bdev == bdev &&
            bh->b_size == size) {
            if (i) {
                while (i) {
                    __this_cpu_write(bh_lrus.bhs[i],
                        __this_cpu_read(bh_lrus.bhs[i - 1]));
                    i--;
                }
                __this_cpu_write(bh_lrus.bhs[0], bh);
            }
            get_bh(bh);
            ret = bh;
            break;
        }
    }
    bh_lru_unlock();

    // === test code begin ===
    if(ret) {
        printk("[%s]: ret is not NULL\n", __func__);
    } else {
        printk("[%s]: ret is NULL\n", __func__);
    }
    // === test code end ===

    return ret;
}

static struct buffer_head *
__my_find_get_block_slow(struct block_device *bdev, sector_t block)
{
    struct inode *bd_inode = bdev->bd_inode;
    struct address_space *bd_mapping = bd_inode->i_mapping;
    struct buffer_head *ret = NULL;
    pgoff_t index;
    struct buffer_head *bh;
    struct buffer_head *head;
    struct folio *folio;
    int all_mapped = 1;
    static DEFINE_RATELIMIT_STATE(last_warned, HZ, 1);

    index = block >> (PAGE_SHIFT - bd_inode->i_blkbits);
    folio = __filemap_get_folio(bd_mapping, index, FGP_ACCESSED, 0);
    if (IS_ERR(folio))
        goto out;

    spin_lock(&bd_mapping->private_lock);
    head = folio_buffers(folio);
    if (!head)
        goto out_unlock;
    bh = head;
    do {
        if (!buffer_mapped(bh))
            all_mapped = 0;
        else if (bh->b_blocknr == block) {
            ret = bh;
            get_bh(bh);
            goto out_unlock;
        }
        bh = bh->b_this_page;
    } while (bh != head);

    /* we might be here because some of the buffers on this page are
     * not mapped.  This is due to various races between
     * file io on the block device and getblk.  It gets dealt with
     * elsewhere, don't buffer_error if we had some unmapped buffers
     */
    ratelimit_set_flags(&last_warned, RATELIMIT_MSG_ON_RELEASE);
    if (all_mapped && __ratelimit(&last_warned)) {
        printk("__find_get_block_slow() failed. block=%llu, "
               "b_blocknr=%llu, b_state=0x%08lx, b_size=%zu, "
               "device %pg blocksize: %d\n",
               (unsigned long long)block,
               (unsigned long long)bh->b_blocknr,
               bh->b_state, bh->b_size, bdev,
               1 << bd_inode->i_blkbits);
    }
out_unlock:
    spin_unlock(&bd_mapping->private_lock);
    folio_put(folio);
out:
    return ret;
}

static void my_bh_lru_install(struct buffer_head *bh)
{
    struct buffer_head *evictee = bh;
    struct bh_lru *b;
    int i;

    check_irqs_on();
    bh_lru_lock();

    /*
     * the refcount of buffer_head in bh_lru prevents dropping the
     * attached page(i.e., try_to_free_buffers) so it could cause
     * failing page migration.
     * Skip putting upcoming bh into bh_lru until migration is done.
     */
    if (lru_cache_disabled() || cpu_is_isolated(smp_processor_id())) {
        bh_lru_unlock();
        return;
    }

    b = this_cpu_ptr(&bh_lrus);
    for (i = 0; i < BH_LRU_SIZE; i++) {
        swap(evictee, b->bhs[i]);
        if (evictee == bh) {
            bh_lru_unlock();
            return;
        }
    }

    get_bh(bh);
    bh_lru_unlock();
    brelse(evictee);
}

inline void my_touch_buffer(struct buffer_head *bh)
{
    trace_block_touch_buffer(bh);
    folio_mark_accessed(bh->b_folio);
}
EXPORT_SYMBOL(my_touch_buffer);

/*
 * Perform a pagecache lookup for the matching buffer.  If it's there, refresh
 * it in the LRU and mark it as accessed.  If it is not present then return
 * NULL
 */
struct buffer_head *
__my_find_get_block(struct block_device *bdev, sector_t block, unsigned size)
{
    struct buffer_head *bh = my_lookup_bh_lru(bdev, block, size);

    // === test code ===
    if(bh) {
        printk("[%s]: bh(my_lookup_bh_lru()'s result) is not NULL", __func__); 
    } else {
        printk("[%s]: bh(my_lookup_bh_lru()'s result) is NULL", __func__); 
    }
    // === test code ===

    if (bh == NULL) {
        /* __find_get_block_slow will mark the page accessed */
        bh = __my_find_get_block_slow(bdev, block);
        
        // === test code ===
        if(bh) {
            printk("[%s]: bh(__my_find_get_block_slow()'s result) is not NULL", __func__); 
        } else {
            printk("[%s]: bh(__my_find_get_block_slow()'s result) is NULL", __func__); 
        }
        // === test code ===
        
        if (bh)
            my_bh_lru_install(bh);
    } else {
        my_touch_buffer(bh);
        
        // === test code ===
        if(bh) {
            printk("[%s]: bh(my_touch_buffer()'s result) is not NULL", __func__); 
        } else {
            printk("[%s]: bh(my_touch_buffer()'s result) is NULL", __func__); 
        }
        // === test code ===
    }

    return bh;
}
EXPORT_SYMBOL(__my_find_get_block);

/*
 * Create the page-cache page that contains the requested block.
 *
 * This is used purely for blockdev mappings.
 */
static int
my_grow_dev_page(struct block_device *bdev, sector_t block,
          pgoff_t index, int size, int sizebits, gfp_t gfp)
{
    struct inode *inode = bdev->bd_inode;
    struct folio *folio;
    struct buffer_head *bh;
    sector_t end_block;
    int ret = 0;
    gfp_t gfp_mask;

    gfp_mask = mapping_gfp_constraint(inode->i_mapping, ~__GFP_FS) | gfp;

    /*
     * XXX: __getblk_slow() can not really deal with failure and
     * will endlessly loop on improvised global reclaim.  Prefer
     * looping in the allocator rather than here, at least that
     * code knows what it's doing.
     */
    gfp_mask |= __GFP_NOFAIL;

    folio = __filemap_get_folio(inode->i_mapping, index,
            FGP_LOCK | FGP_ACCESSED | FGP_CREAT, gfp_mask);

    bh = folio_buffers(folio);
    if (bh) {
        if (bh->b_size == size) {
            end_block = folio_init_buffers(folio, bdev,
                    (sector_t)index << sizebits, size);
            goto done;
        }
        if (!try_to_free_buffers(folio))
            goto failed;
    }

    bh = folio_alloc_buffers(folio, size, true);

    /*
     * Link the folio to the buffers and initialise them.  Take the
     * lock to be atomic wrt __find_get_block(), which does not
     * run under the folio lock.
     */
    spin_lock(&inode->i_mapping->private_lock);
    link_dev_buffers(folio, bh);
    end_block = folio_init_buffers(folio, bdev,
            (sector_t)index << sizebits, size);
    spin_unlock(&inode->i_mapping->private_lock);
done:
    ret = (block < end_block) ? 1 : -ENXIO;
failed:
    folio_unlock(folio);
    folio_put(folio);
    return ret;
}

/*
 * Create buffers for the specified block device block's page.  If
 * that page was dirty, the buffers are set dirty also.
 */
static int
my_grow_buffers(struct block_device *bdev, sector_t block, int size, gfp_t gfp)
{
    pgoff_t index;
    int sizebits;

    sizebits = PAGE_SHIFT - __ffs(size);
    index = block >> sizebits;

    /*
     * Check for a block which wants to lie outside our maximum possible
     * pagecache index.  (this comparison is done using sector_t types).
     */
    if (unlikely(index != block >> sizebits)) {
        printk(KERN_ERR "%s: requested out-of-range block %llu for "
            "device %pg\n",
            __func__, (unsigned long long)block,
            bdev);
        return -EIO;
    }

    /* Create a page with the proper size buffers.. */
    return my_grow_dev_page(bdev, block, index, size, sizebits, gfp);
}

static struct buffer_head *
__my_getblk_slow(struct block_device *bdev, sector_t block,
         unsigned size, gfp_t gfp)
{
    /* Size must be multiple of hard sectorsize */
    if (unlikely(size & (bdev_logical_block_size(bdev)-1) ||
            (size < 512 || size > PAGE_SIZE))) {
        printk(KERN_ERR "getblk(): invalid block size %d requested\n",
                    size);
        printk(KERN_ERR "logical block size: %d\n",
                    bdev_logical_block_size(bdev));

        dump_stack();
        return NULL;
    }

    for (;;) {
        struct buffer_head *bh;
        int ret;

        bh = __my_find_get_block(bdev, block, size);
        if (bh)
            return bh;

        ret = my_grow_buffers(bdev, block, size, gfp);
        if (ret < 0)
            return NULL;
    }
}

/*
 * __getblk_gfp() will locate (and, if necessary, create) the buffer_head
 * which corresponds to the passed block_device, block and size. The
 * returned buffer has its reference count incremented.
 *
 * __getblk_gfp() will lock up the machine if grow_dev_page's
 * try_to_free_buffers() attempt is failing.  FIXME, perhaps?
 */
struct buffer_head *
__my_getblk_gfp(struct block_device *bdev, sector_t block,
                 unsigned size, gfp_t gfp)
{
    struct buffer_head *bh = __my_find_get_block(bdev, block, size);
    printk("[%s]: bdev->bd_disk->disk_name= %s\n", __func__, bdev->bd_disk->disk_name); // test code
    printk("[%s]: block= %llu\n", __func__, block); // test code
    printk("[%s]: block= %u\n", __func__, size); // test code

    if(bh) {
        printk("[%s]: bh is not NULL", __func__); // test code
    } else {
        printk("[%s]: bh is NULL", __func__); // test code
    }

    might_sleep();
    if (bh == NULL)
        bh = __my_getblk_slow(bdev, block, size, gfp);
   
    if(bh) {
        printk("[%s]: bh is not NULL", __func__); // test code
    } else {
        printk("[%s]: bh is NULL", __func__); // test code
    }

    return bh;
}
EXPORT_SYMBOL(__my_getblk_gfp);
