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
extern void folio_memcg_lock(struct folio *folio);
extern void __folio_mark_dirty(struct folio *folio, struct address_space *mapping, int warn);
extern void folio_memcg_unlock(struct folio *folio);
extern bool node_set_mark(struct xa_node *node, unsigned int offset, xa_mark_t mark);
extern void folio_account_dirtied(struct folio *folio, struct address_space *mapping);
extern void xa_mark_set(struct xarray *xa, xa_mark_t mark);
extern void wb_wakeup_delayed(struct bdi_writeback *wb);

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
            printk("[%s]: The %d-th element is in the cache — a cache hit occurs", __func__, i); // test code
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

static inline struct xa_node *my_xa_to_node(const void *entry)
{
    return (struct xa_node *)((unsigned long)entry - 2);
}

static unsigned int my_get_offset(unsigned long index, struct xa_node *node)
{
    return (index >> node->shift) & XA_CHUNK_MASK;
}

static void *my_xas_descend(struct xa_state *xas, struct xa_node *node)
{
    unsigned int offset = my_get_offset(xas->xa_index, node);
    void *entry = xa_entry(xas->xa, node, offset);

    // printk("[%s]: 0\n", __func__); // test code
    printk("[%s]: offset= %u\n", __func__, offset); // test code

    xas->xa_node = node;
    while (xa_is_sibling(entry)) {
        printk("[%s]: 1\n", __func__); // test code
        offset = xa_to_sibling(entry);
        entry = xa_entry(xas->xa, node, offset);
        if (node->shift && xa_is_node(entry)) {
            printk("[%s]: 2\n", __func__); // test code
            entry = XA_RETRY_ENTRY;
        }
    }
    // printk("[%s]: 3\n", __func__); // test code

    xas->xa_offset = offset;
    return entry;
}

/**
 * xas_invalid() - Is the xas in a retry or error state?
 * @xas: XArray operation state.
 *
 * Return: %true if the xas cannot be used for operations.
 */
static inline bool my_xas_invalid(const struct xa_state *xas)
{
    return (unsigned long)xas->xa_node & 3;
}

/**
 * xas_valid() - Is the xas a valid cursor into the array?
 * @xas: XArray operation state.
 *
 * Return: %true if the xas can be used for operations.
 */
static inline bool my_xas_valid(const struct xa_state *xas)
{
    return !my_xas_invalid(xas);
}

/**
 * xa_is_err() - Report whether an XArray operation returned an error
 * @entry: Result from calling an XArray function
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special value indicating an error.  This function tells you
 * whether an error occurred; xa_err() tells you which error occurred.
 *
 * Context: Any context.
 * Return: %true if the entry indicates an error.
 */
static inline bool my_xa_is_err(const void *entry)
{
    return unlikely(xa_is_internal(entry) &&
            entry >= xa_mk_internal(-MAX_ERRNO));
}

/**
 * xa_err() - Turn an XArray result into an errno.
 * @entry: Result from calling an XArray function.
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special pointer value which encodes an errno.  This function extracts
 * the errno from the pointer value, or returns 0 if the pointer does not
 * represent an errno.
 *
 * Context: Any context.
 * Return: A negative errno or 0.
 */
static inline int my_xa_err(void *entry)
{
    /* xa_to_internal() would not do sign extension. */
    if (my_xa_is_err(entry))
        return (long)entry >> 2;
    return 0;
}

/**
 * xas_error() - Return an errno stored in the xa_state.
 * @xas: XArray operation state.
 *
 * Return: 0 if no error has been noted.  A negative errno if one has.
 */
static inline int my_xas_error(const struct xa_state *xas)
{
    return my_xa_err(xas->xa_node);
}

/* Private */
static inline void *my_xa_head(const struct xarray *xa)
{
    return rcu_dereference_check(xa->xa_head,
                        lockdep_is_held(&xa->xa_lock));
}

/* Private */
static inline bool my_xa_is_node(const void *entry)
{
    return xa_is_internal(entry) && (unsigned long)entry > 4096;
}

static void *my_set_bounds(struct xa_state *xas)
{
    xas->xa_node = XAS_BOUNDS;
    return NULL;
}

/*
 * Starts a walk.  If the @xas is already valid, we assume that it's on
 * the right path and just return where we've got to.  If we're in an
 * error state, return NULL.  If the index is outside the current scope
 * of the xarray, return NULL without changing @xas->xa_node.  Otherwise
 * set @xas->xa_node to NULL and return the current head of the array.
 */
static void *my_xas_start(struct xa_state *xas)
{
    void *entry;

    printk("[%s]: 0\n", __func__); // test code

    if (my_xas_valid(xas)) {
        printk("[%s]: 1\n", __func__); // test code
        return xas_reload(xas);
    }
    if (my_xas_error(xas)) {
        printk("[%s]: 2\n", __func__); // test code
        return NULL;
    }

    printk("[%s]: 3\n", __func__); // test code
    
    entry = my_xa_head(xas->xa);
    if (!my_xa_is_node(entry)) {
        printk("[%s]: 4\n", __func__); // test code
        if (xas->xa_index) {
            printk("[%s]: 5\n", __func__); // test code
            return my_set_bounds(xas);
        }
    } else {
        printk("[%s]: 6\n", __func__); // test code
        if ((xas->xa_index >> my_xa_to_node(entry)->shift) > XA_CHUNK_MASK) {
            printk("[%s]: 7\n", __func__); // test code
            return my_set_bounds(xas);
        }
    }
    printk("[%s]: 8\n", __func__); // test code

    xas->xa_node = NULL;
    return entry;
}

/**
 * xas_load() - Load an entry from the XArray (advanced).
 * @xas: XArray operation state.
 *
 * Usually walks the @xas to the appropriate state to load the entry
 * stored at xa_index.  However, it will do nothing and return %NULL if
 * @xas is in an error state.  xas_load() will never expand the tree.
 *
 * If the xa_state is set up to operate on a multi-index entry, xas_load()
 * may return %NULL or an internal entry, even if there are entries
 * present within the range specified by @xas.
 *
 * Context: Any context.  The caller should hold the xa_lock or the RCU lock.
 * Return: Usually an entry in the XArray, but see description for exceptions.
 */
void *my_xas_load(struct xa_state *xas)
{
    void *entry = my_xas_start(xas); // add EXPORT_SYMBOL

    printk("[%s]: 0\n", __func__); // test code

    while (xa_is_node(entry)) {
        struct xa_node *node = my_xa_to_node(entry); // add EXPORT_SYMBOL 
                                                     
        printk("[%s]: 1\n", __func__); // test code

        printk("[%s]: xas->xa_shift: %u\n", __func__, xas->xa_shift); // test code
        printk("[%s]: node->shift: %u\n", __func__, node->shift); // test code
                                                                  
        if(node->offset) {                                                                 
            printk("[%s]: node->offset: %u\n", __func__, node->offset); // test code
        } else {
            printk("[%s]: node->offset is NULL", __func__); // test code
        }

        if (xas->xa_shift > node->shift) {
            printk("[%s]: 2\n", __func__); // test code
            break;
        }

        printk("[%s]: 3\n", __func__); // test code
        
        entry = my_xas_descend(xas, node);
        if (node->shift == 0) {
            printk("[%s]: 4\n", __func__); // test code
            // printk("[%s]: The address entry is pointing to: %p\n", __func__, entry); // test code
            break;
        }
        printk("[%s]: 5\n", __func__); // test code
    }
    printk("[%s]: 6\n", __func__); // test code
    return entry;
}

/**
 * xas_set_mark() - Sets the mark on this entry and its parents.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Sets the specified mark on this entry, and walks up the tree setting it
 * on all the ancestor entries.  Does nothing if @xas has not been walked to
 * an entry, or is in an error state.
 */
void my_xas_set_mark(const struct xa_state *xas, xa_mark_t mark)
{
    struct xa_node *node = xas->xa_node;
    unsigned int offset = xas->xa_offset;

    // printk("[%s]: 0\n", __func__); // test code
    printk("[%s]: xas->xa_offset = %u\n", __func__, xas->xa_offset); // test code

    if (xas_invalid(xas)) {
        // printk("[%s]: 1\n", __func__); // test code
        return;
    }
    // printk("[%s]: 2\n", __func__); // test code

    while (node) {
        // printk("[%s]: 3\n", __func__); // test code
        if (node_set_mark(node, offset, mark)) {
            // printk("[%s]: 4\n", __func__); // test code
            return;
        }
        // printk("[%s]: 5\n", __func__); // test code
        offset = node->offset;
        node = xa_parent_locked(xas->xa, node);
    }
    // printk("[%s]: 6\n", __func__); // test code

    if (!xa_marked(xas->xa, mark)) {
        // printk("[%s]: 7\n", __func__); // test code
        xa_mark_set(xas->xa, mark);
    }
}

/**
 * __xa_set_mark() - Set this mark on this entry while locked.
 * @xa: XArray.
 * @index: Index of entry.
 * @mark: Mark number.
 *
 * Attempting to set a mark on a %NULL entry does not succeed.
 *
 * Context: Any context.  Expects xa_lock to be held on entry.
 */
void __my_xa_set_mark(struct xarray *xa, unsigned long index, xa_mark_t mark)
{
    XA_STATE(xas, xa, index);

    printk("[%s]: xas.xa_index= %lu\n", __func__, xas.xa_index); // test code

    void *entry = my_xas_load(&xas);
    
    if (entry)
        my_xas_set_mark(&xas, mark);
}

/*
 * Mark the folio dirty, and set it dirty in the page cache, and mark
 * the inode dirty.
 *
 * If warn is true, then emit a warning if the folio is not uptodate and has
 * not been truncated.
 *
 * The caller must hold folio_memcg_lock().  Most callers have the folio
 * locked.  A few have the folio blocked from truncation through other
 * means (eg zap_vma_pages() has it mapped and is holding the page table
 * lock).  This can also be called from mark_buffer_dirty(), which I
 * cannot prove is always protected against truncate.
 */
void __my_folio_mark_dirty(struct folio *folio, struct address_space *mapping,
                 int warn)
{
    unsigned long flags;

    xa_lock_irqsave(&mapping->i_pages, flags);
    if (folio->mapping) {   /* Race with truncate? */
        WARN_ON_ONCE(warn && !folio_test_uptodate(folio));
        folio_account_dirtied(folio, mapping);
        __my_xa_set_mark(&mapping->i_pages, folio_index(folio),
                PAGECACHE_TAG_DIRTY);
    }
    xa_unlock_irqrestore(&mapping->i_pages, flags);
}

/**
 * locked_inode_to_wb_and_lock_list - determine a locked inode's wb and lock it
 * @inode: inode of interest with i_lock held
 *
 * Returns @inode's wb with its list_lock held.  @inode->i_lock must be
 * held on entry and is released on return.  The returned wb is guaranteed
 * to stay @inode's associated wb until its list_lock is released.
 */
static struct bdi_writeback *
my_locked_inode_to_wb_and_lock_list(struct inode *inode)
    __releases(&inode->i_lock)
    __acquires(&wb->list_lock)
{
    while (true) {
        struct bdi_writeback *wb = inode_to_wb(inode);

        printk("[%s]: 0\n", __func__); // test code

        /*
         * inode_to_wb() association is protected by both
         * @inode->i_lock and @wb->list_lock but list_lock nests
         * outside i_lock.  Drop i_lock and verify that the
         * association hasn't changed after acquiring list_lock.
         */
        wb_get(wb);
        spin_unlock(&inode->i_lock);
        spin_lock(&wb->list_lock);

        /* i_wb may have changed inbetween, can't use inode_to_wb() */
        if (likely(wb == inode->i_wb)) {
            printk("[%s]: 1\n", __func__); // test code
            
            wb_put(wb); /* @inode already has ref */
            return wb;
        }
        printk("[%s]: 2\n", __func__); // test code

        spin_unlock(&wb->list_lock);
        wb_put(wb);
        cpu_relax();
        spin_lock(&inode->i_lock);
    }
}

static bool my_wb_io_lists_populated(struct bdi_writeback *wb)
{
    if (wb_has_dirty_io(wb)) {
        printk("[%s]: 0\n", __func__); // test code
        
        return false;
    } else {
        printk("[%s]: 1\n", __func__); // test code
        printk("[%s]: WB_has_dirty_io= %d\n", __func__, WB_has_dirty_io); // test code
        
        printk("[%s]: wb->state(before set_bit)= %lu\n", __func__, wb->state); // test code

        set_bit(WB_has_dirty_io, &wb->state);
        
        printk("[%s]: wb->state(after set_bit)= %lu\n", __func__, wb->state); // test code
        
        WARN_ON_ONCE(!wb->avg_write_bandwidth);
        atomic_long_add(wb->avg_write_bandwidth,
                &wb->bdi->tot_write_bandwidth);
        return true;
    }
}

static void my_wb_io_lists_depopulated(struct bdi_writeback *wb)
{
    if (wb_has_dirty_io(wb) && list_empty(&wb->b_dirty) &&
        list_empty(&wb->b_io) && list_empty(&wb->b_more_io)) {
        printk("[%s]: 0\n", __func__); // test code
        
        clear_bit(WB_has_dirty_io, &wb->state);
        WARN_ON_ONCE(atomic_long_sub_return(wb->avg_write_bandwidth,
                    &wb->bdi->tot_write_bandwidth) < 0);
    }
    printk("[%s]: 1\n", __func__); // test code
}

/**
 * inode_io_list_move_locked - move an inode onto a bdi_writeback IO list
 * @inode: inode to be moved
 * @wb: target bdi_writeback
 * @head: one of @wb->b_{dirty|io|more_io|dirty_time}
 *
 * Move @inode->i_io_list to @list of @wb and set %WB_has_dirty_io.
 * Returns %true if @inode is the first occupant of the !dirty_time IO
 * lists; otherwise, %false.
 */
static bool my_inode_io_list_move_locked(struct inode *inode,
                      struct bdi_writeback *wb,
                      struct list_head *head)
{
    assert_spin_locked(&wb->list_lock);
    assert_spin_locked(&inode->i_lock);
    WARN_ON_ONCE(inode->i_state & I_FREEING);

    list_move(&inode->i_io_list, head);
    
    printk("[%s]: 0\n", __func__); // test code

    /* dirty_time doesn't count as dirty_io until expiration */
    if (head != &wb->b_dirty_time) {
        printk("[%s]: 1\n", __func__); // test code
        return my_wb_io_lists_populated(wb);
    }
    printk("[%s]: 2\n", __func__); // test code

    my_wb_io_lists_depopulated(wb);
    return false;
}

/**
 * __mark_inode_dirty - internal function to mark an inode dirty
 *
 * @inode: inode to mark
 * @flags: what kind of dirty, e.g. I_DIRTY_SYNC.  This can be a combination of
 *     multiple I_DIRTY_* flags, except that I_DIRTY_TIME can't be combined
 *     with I_DIRTY_PAGES.
 *
 * Mark an inode as dirty.  We notify the filesystem, then update the inode's
 * dirty flags.  Then, if needed we add the inode to the appropriate dirty list.
 *
 * Most callers should use mark_inode_dirty() or mark_inode_dirty_sync()
 * instead of calling this directly.
 *
 * CAREFUL!  We only add the inode to the dirty list if it is hashed or if it
 * refers to a blockdev.  Unhashed inodes will never be added to the dirty list
 * even if they are later hashed, as they will have been marked dirty already.
 *
 * In short, ensure you hash any inodes _before_ you start marking them dirty.
 *
 * Note that for blockdevs, inode->dirtied_when represents the dirtying time of
 * the block-special inode (/dev/hda1) itself.  And the ->dirtied_when field of
 * the kernel-internal blockdev inode represents the dirtying time of the
 * blockdev's pages.  This is why for I_DIRTY_PAGES we always use
 * page->mapping->host, so the page-dirtying time is recorded in the internal
 * blockdev inode.
 */
void __my_mark_inode_dirty(struct inode *inode, int flags)
{
    struct super_block *sb = inode->i_sb;
    int dirtytime = 0;
    struct bdi_writeback *wb = NULL;

    printk("[%s]: 0\n", __func__); // test code
    printk("[%s]: flags= %d\n", __func__, flags); // test code
    printk("[%s]: I_DIRTY_INODE= %d\n", __func__, I_DIRTY_INODE); // test code 
    printk("[%s]: I_DIRTY_TIME= %d\n", __func__, I_DIRTY_TIME); // test code 

    // trace_writeback_mark_inode_dirty(inode, flags);

    if (flags & I_DIRTY_INODE) {
        printk("[%s]: 1\n", __func__); // test code
        /*
         * Inode timestamp update will piggback on this dirtying.
         * We tell ->dirty_inode callback that timestamps need to
         * be updated by setting I_DIRTY_TIME in flags.
         */
        if (inode->i_state & I_DIRTY_TIME) {
            printk("[%s]: 2\n", __func__); // test code
            spin_lock(&inode->i_lock);
            if (inode->i_state & I_DIRTY_TIME) {
                printk("[%s]: 3\n", __func__); // test code
                inode->i_state &= ~I_DIRTY_TIME;
                flags |= I_DIRTY_TIME;
            }
            printk("[%s]: 4\n", __func__); // test code
            spin_unlock(&inode->i_lock);
        }

        printk("[%s]: 5\n", __func__); // test code

        /*
         * Notify the filesystem about the inode being dirtied, so that
         * (if needed) it can update on-disk fields and journal the
         * inode.  This is only needed when the inode itself is being
         * dirtied now.  I.e. it's only needed for I_DIRTY_INODE, not
         * for just I_DIRTY_PAGES or I_DIRTY_TIME.
         */
        // trace_writeback_dirty_inode_start(inode, flags);
        if (sb->s_op->dirty_inode) {
            printk("[%s]: 6\n", __func__); // test code
            sb->s_op->dirty_inode(inode,
                flags & (I_DIRTY_INODE | I_DIRTY_TIME));
        }

        printk("[%s]: 7\n", __func__); // test code
                                      
        // trace_writeback_dirty_inode(inode, flags);

        /* I_DIRTY_INODE supersedes I_DIRTY_TIME. */
        flags &= ~I_DIRTY_TIME;
    } else {
        /*
         * Else it's either I_DIRTY_PAGES, I_DIRTY_TIME, or nothing.
         * (We don't support setting both I_DIRTY_PAGES and I_DIRTY_TIME
         * in one call to __mark_inode_dirty().)
         */

        printk("[%s]: 8\n", __func__); // test code
        
        dirtytime = flags & I_DIRTY_TIME;
        
        printk("[%s]: dirtytime= %d\n", __func__, dirtytime); // test code

        WARN_ON_ONCE(dirtytime && flags != I_DIRTY_TIME);
    }
    
    printk("[%s]: 9\n", __func__); // test code

    /*
     * Paired with smp_mb() in __writeback_single_inode() for the
     * following lockless i_state test.  See there for details.
     */
    smp_mb();

    if ((inode->i_state & flags) == flags) {
        printk("[%s]: 10\n", __func__); // test code
        return;
    }

    printk("[%s]: 11\n", __func__); // test code

    spin_lock(&inode->i_lock);
    if ((inode->i_state & flags) != flags) {
        
        printk("[%s]: 12\n", __func__); // test code
                                     
        const int was_dirty = inode->i_state & I_DIRTY;

        printk("[%s]: inode->i_state= %lu\n", __func__, inode->i_state); // test code
        printk("[%s]: I_DIRTY= %d\n", __func__, I_DIRTY); // test code
        printk("[%s]: was_dirty= %d\n", __func__, was_dirty); // test code

        /*
        // === test code begin ===
        if(inode->i_wb) {
            printk("[%s]: node->i_wb= %p\n", __func__, inode->i_wb);
        } else {
            printk("[%s]: inode->i_wb is NULL\n", __func__);
        }
        // === test code end ===
        */
            
        inode_attach_wb(inode, NULL);

        /*
        // === test code begin ===
        if(inode->i_wb) {
            printk("[%s]: node->i_wb= %p\n", __func__, inode->i_wb);
        } else {
            printk("[%s]: inode->i_wb is NULL\n", __func__);
        }
        // === test code end ===
        */

        inode->i_state |= flags;

        printk("[%s]: inode->i_state(after '|= flags;')= %lu\n", __func__, inode->i_state); // test code

        /*
         * Grab inode's wb early because it requires dropping i_lock and we
         * need to make sure following checks happen atomically with dirty
         * list handling so that we don't move inodes under flush worker's
         * hands.
         */
        if (!was_dirty) {

            printk("[%s]: 13\n", __func__); // test code
                                         
            wb = my_locked_inode_to_wb_and_lock_list(inode);
            spin_lock(&inode->i_lock);
        }

        printk("[%s]: 14\n", __func__); // test code

        /*
         * If the inode is queued for writeback by flush worker, just
         * update its dirty state. Once the flush worker is done with
         * the inode it will place it on the appropriate superblock
         * list, based upon its state.
         */
        if (inode->i_state & I_SYNC_QUEUED) {

            printk("[%s]: 15\n", __func__); // test code
                                          
            goto out_unlock;
        }
    
        printk("[%s]: 16\n", __func__); // test code

        /*
         * Only add valid (hashed) inodes to the superblock's
         * dirty list.  Add blockdev inodes as well.
         */
        if (!S_ISBLK(inode->i_mode)) {
            
            printk("[%s]: 17\n", __func__); // test code

            if (inode_unhashed(inode)) {

                printk("[%s]: 18\n", __func__); // test code
                                              
                goto out_unlock;
            }
        }
        
        printk("[%s]: 19\n", __func__); // test code

        if (inode->i_state & I_FREEING) {
            printk("[%s]: 20\n", __func__); // test code
            goto out_unlock;
        }

        printk("[%s]: 21\n", __func__); // test code

        /*
         * If the inode was already on b_dirty/b_io/b_more_io, don't
         * reposition it (that would break b_dirty time-ordering).
         */
        if (!was_dirty) {
            struct list_head *dirty_list;
            bool wakeup_bdi = false;

            printk("[%s]: 22\n", __func__); // test code

            inode->dirtied_when = jiffies;
            if (dirtytime) {
                printk("[%s]: 23\n", __func__); // test code
                inode->dirtied_time_when = jiffies;
            }
            
            printk("[%s]: 24\n", __func__); // test code

            if (inode->i_state & I_DIRTY) {
                printk("[%s]: 25\n", __func__); // test code
                dirty_list = &wb->b_dirty;
            }
            else {
                printk("[%s]: 26\n", __func__); // test code
                dirty_list = &wb->b_dirty_time;
            }

            printk("[%s]: 27\n", __func__); // test code
                                  
            wakeup_bdi = my_inode_io_list_move_locked(inode, wb,
                                   dirty_list);

            spin_unlock(&wb->list_lock);
            spin_unlock(&inode->i_lock);
            // trace_writeback_dirty_inode_enqueue(inode);

            /*
             * If this is the first dirty inode for this bdi,
             * we have to wake-up the corresponding bdi thread
             * to make sure background write-back happens
             * later.
             */
            if (wakeup_bdi &&
                (wb->bdi->capabilities & BDI_CAP_WRITEBACK)) {
                printk("[%s]: 28\n", __func__); // test code
                wb_wakeup_delayed(wb);
            }
            
            printk("[%s]: 29\n", __func__); // test code
            
            return;
        }
    }
out_unlock:
    
    printk("[%s]: 29\n", __func__); // test code

    if (wb) {
        printk("[%s]: 30\n", __func__); // test code
        spin_unlock(&wb->list_lock);
    }

    printk("[%s]: 31\n", __func__); // test code
    
    spin_unlock(&inode->i_lock);
}

/**
 * mark_buffer_dirty - mark a buffer_head as needing writeout
 * @bh: the buffer_head to mark dirty
 *
 * mark_buffer_dirty() will set the dirty bit against the buffer, then set
 * its backing page dirty, then tag the page as dirty in the page cache
 * and then attach the address_space's inode to its superblock's dirty
 * inode list.
 *
 * mark_buffer_dirty() is atomic.  It takes bh->b_folio->mapping->private_lock,
 * i_pages lock and mapping->host->i_lock.
 */
void my_mark_buffer_dirty(struct buffer_head *bh)
{
    WARN_ON_ONCE(!buffer_uptodate(bh));
    
    printk("[%s]: The address bh->b_folio is pointing to: %p\n", __func__, bh->b_folio); // test code

    printk("[%s]: 0\n", __func__);

    // comment out this function
    // trace_block_dirty_buffer(bh);

    /*
     * Very *carefully* optimize the it-is-already-dirty case.
     *
     * Don't let the final "is it dirty" escape to before we
     * perhaps modified the buffer.
     */
    if (buffer_dirty(bh)) {
        printk("[%s]: 1\n", __func__);
        smp_mb();
        if (buffer_dirty(bh)) {
            printk("[%s]: 2\n", __func__);
            return;
        }
    }

    if (!test_set_buffer_dirty(bh)) {
        printk("[%s]: 3\n", __func__);
        struct folio *folio = bh->b_folio;
        struct address_space *mapping = NULL;
       
		// === test code begin ===
        if (folio) {
            // index is pgoff_t (usually unsigned long), so use %lu
            pgoff_t idx = folio_index(folio);
            printk("[%s]: folio's index=%lu\n", __func__, (unsigned long)idx);
            /*
            // For a large folio, this will be > 1
            unsigned long nr = folio_nr_pages(folio);

            // File offset in bytes = index << PAGE_SHIFT
            unsigned long long file_off = (unsigned long long)idx << PAGE_SHIFT;

            // The "file offset" is only meaningful if a mapping exists
            mapping = folio->mapping;

            printk("[%s]: folio=%p index=%lu (%llu bytes) nr_pages=%lu mapping=%p\n",
                   __func__, folio,
                   (unsigned long)idx,
                   file_off,
                   (unsigned long)nr,
                   mapping);

            if (mapping && mapping->host) {
                // Also print info like the inode number for reference
                printk("[%s]: inode ino=%lu sb=%p\n",
                       __func__, (unsigned long)mapping->host->i_ino,
                       mapping->host->i_sb);
            }
            */
        } else {
            printk("[%s]: folio is NULL (bh=%p)\n", __func__, bh);
        }
		// === tese code end ===

        folio_memcg_lock(folio);
        if (!folio_test_set_dirty(folio)) {
            printk("[%s]: 4\n", __func__);
            mapping = folio->mapping;
            if (mapping) {
                printk("[%s]: 5\n", __func__);
                __my_folio_mark_dirty(folio, mapping, 0);
            }
        }
        printk("[%s]: 6\n", __func__);
        folio_memcg_unlock(folio);
        if (mapping) {
            printk("[%s]: 7\n", __func__);

            // === test code begin ===
            if(mapping->host) {
                printk("[%s]: mapping->host->i_ino=%lu\n", __func__, mapping->host->i_ino);
                printk("[%s]: mapping->host->i_state=%lu\n", __func__, mapping->host->i_state);
                
            } else {
                printk("[%s]: mapping->host is NULL\n", __func__);
            }
            // === test code end ===

            __my_mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
        }
    }
}
