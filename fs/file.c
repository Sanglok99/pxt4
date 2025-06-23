#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/close_range.h>
#include <net/sock.h>
#include <linux/bitmap.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/swab.h>

#include "internal.h"

unsigned int sysctl_nr_open __read_mostly = 1024*1024;
unsigned int sysctl_nr_open_min = BITS_PER_LONG;
/* our min() is unusable in constant expressions ;-/ */
#define __const_min(x, y) ((x) < (y) ? (x) : (y))
unsigned int sysctl_nr_open_max =
    __const_min(INT_MAX, ~(size_t)0/sizeof(void *)) & -BITS_PER_LONG;

extern int expand_files(struct files_struct *files, unsigned int nr);
extern inline void __set_close_on_exec(unsigned int fd, struct fdtable *fdt);
extern inline void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt);

#define BITBIT_NR(nr)   BITS_TO_LONGS(BITS_TO_LONGS(nr))
#define BITBIT_SIZE(nr) (BITBIT_NR(nr) * sizeof(long))

#define MY_FIND_NEXT_BIT(FETCH, MUNGE, size, start)                \
({                                      \
    unsigned long mask, idx, tmp, sz = (size), __start = (start);       \
                                        \
    printk("[%s]: sz: %lu\n", __func__, sz);            \
    printk("[%s]: __start: %lu\n", __func__, __start);          \
                                                        \
    if (unlikely(__start >= sz))                        \
        goto out;                           \
                                        \
    mask = MUNGE(BITMAP_FIRST_WORD_MASK(__start));              \
    printk("[%s]: mask: %lu\n", __func__, mask);                \
    idx = __start / BITS_PER_LONG;                      \
    printk("[%s]: idx: %lu\n", __func__, idx);                  \
                                        \
    for (tmp = (FETCH) & mask; !tmp; tmp = (FETCH)) {           \
        if ((idx + 1) * BITS_PER_LONG >= sz)                \
            goto out;                       \
        idx++;                              \
    }                                   \
                                        \
    sz = min(idx * BITS_PER_LONG + __ffs(MUNGE(tmp)), sz);          \
out:                                        \
    sz;                                 \
})

#ifndef find_next_zero_bit
unsigned long _my_find_next_zero_bit(const unsigned long *addr, unsigned long nbits,
                     unsigned long start)
{
    return MY_FIND_NEXT_BIT(~addr[idx], /* nop */, nbits, start);
}
#endif

#ifndef find_next_zero_bit
/**
 * find_next_zero_bit - find the next cleared bit in a memory region
 * @addr: The address to base the search on
 * @size: The bitmap size in bits
 * @offset: The bitnumber to start searching at
 *
 * Returns the bit number of the next zero bit
 * If no bits are zero, returns @size.
 */
static inline
unsigned long my_find_next_zero_bit(const unsigned long *addr, unsigned long size,
                 unsigned long offset)
{
    if (small_const_nbits(size)) {
        unsigned long val;

        if (unlikely(offset >= size))
            return size;

        val = *addr | ~GENMASK(size - 1, offset);
        return val == ~0UL ? size : ffz(val);
    }

    return _my_find_next_zero_bit(addr, size, offset);
}
#endif

inline void __my_set_open_fd(unsigned int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->open_fds);
	fd /= BITS_PER_LONG;
	if (!~fdt->open_fds[fd])
		__set_bit(fd, fdt->full_fds_bits);
}

unsigned int my_find_next_fd(struct fdtable *fdt, unsigned int start)
{
	unsigned int maxfd = fdt->max_fds;
	unsigned int maxbit = maxfd / BITS_PER_LONG;
	unsigned int bitbit = start / BITS_PER_LONG;
    
    printk("[%s]: maxfd: %d, start: %d", __func__, maxfd, start);

	bitbit = my_find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;
	if (bitbit > maxfd)
		return maxfd;
	if (bitbit > start)
		start = bitbit;
	return my_find_next_zero_bit(fdt->open_fds, maxfd, start);
}

static struct fdtable * my_alloc_fdtable(unsigned int nr)
{
    struct fdtable *fdt;
    void *data;

    /*
     * Figure out how many fds we actually want to support in this fdtable.
     * Allocation steps are keyed to the size of the fdarray, since it
     * grows far faster than any of the other dynamic data. We try to fit
     * the fdarray into comfortable page-tuned chunks: starting at 1024B
     * and growing in powers of two from there on.
     */
	printk("[%s]: nr: %u\n", __func__, nr); // test code
    
	nr /= (1024 / sizeof(struct file *));
	
	printk("[%s]: nr: %u\n", __func__, nr); // test code
    
	nr = roundup_pow_of_two(nr + 1);
	
	printk("[%s]: nr: %u\n", __func__, nr); // test code
    
	nr *= (1024 / sizeof(struct file *));
	
	printk("[%s]: nr: %u\n", __func__, nr); // test code
    
	nr = ALIGN(nr, BITS_PER_LONG);
	
	printk("[%s]: nr: %u\n", __func__, nr); // test code
    /*
     * Note that this can drive nr *below* what we had passed if sysctl_nr_open
     * had been set lower between the check in expand_files() and here.  Deal
     * with that in caller, it's cheaper that way.
     *
     * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
     * bitmaps handling below becomes unpleasant, to put it mildly...
     */
    if (unlikely(nr > sysctl_nr_open))
        nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

    fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL_ACCOUNT);
    if (!fdt)
        goto out;
    fdt->max_fds = nr;
    data = kvmalloc_array(nr, sizeof(struct file *), GFP_KERNEL_ACCOUNT);
    if (!data)
        goto out_fdt;
    fdt->fd = data;

    data = kvmalloc(max_t(size_t,
                 2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES),
                 GFP_KERNEL_ACCOUNT);
    if (!data)
        goto out_arr;
    fdt->open_fds = data;
    data += nr / BITS_PER_BYTE;
    fdt->close_on_exec = data;
    data += nr / BITS_PER_BYTE;
    fdt->full_fds_bits = data;

    return fdt;

out_arr:
    kvfree(fdt->fd);
out_fdt:
    kfree(fdt);
out:
    return NULL;
}

/*
 * Copy all file descriptors from the old table to the new, expanded table and
 * clear the extra space.  Called with the files spinlock held for write.
 */

static void my_copy_fd_bitmaps(struct fdtable *nfdt, struct fdtable *ofdt,
                unsigned int count)
{
    unsigned int cpy, set;

    cpy = count / BITS_PER_BYTE;
    set = (nfdt->max_fds - count) / BITS_PER_BYTE;
    memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
    memset((char *)nfdt->open_fds + cpy, 0, set);
    memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
    memset((char *)nfdt->close_on_exec + cpy, 0, set);

    cpy = BITBIT_SIZE(count);
    set = BITBIT_SIZE(nfdt->max_fds) - cpy;
    memcpy(nfdt->full_fds_bits, ofdt->full_fds_bits, cpy);
    memset((char *)nfdt->full_fds_bits + cpy, 0, set);
}

static void my_copy_fdtable(struct fdtable *nfdt, struct fdtable *ofdt)
{
    size_t cpy, set;

    BUG_ON(nfdt->max_fds < ofdt->max_fds);

    cpy = ofdt->max_fds * sizeof(struct file *);
    set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);
    memcpy(nfdt->fd, ofdt->fd, cpy);
    memset((char *)nfdt->fd + cpy, 0, set);

    my_copy_fd_bitmaps(nfdt, ofdt, ofdt->max_fds);
}

static void __my_free_fdtable(struct fdtable *fdt)
{
    kvfree(fdt->fd);
    kvfree(fdt->open_fds);
    kfree(fdt);
}

static void my_free_fdtable_rcu(struct rcu_head *rcu)
{
    __my_free_fdtable(container_of(rcu, struct fdtable, rcu));
}

static int my_expand_fdtable(struct files_struct *files, unsigned int nr)
    __releases(files->file_lock)
    __acquires(files->file_lock)
{
    struct fdtable *new_fdt, *cur_fdt;

    spin_unlock(&files->file_lock);
    new_fdt = my_alloc_fdtable(nr); // alloc_fdtable customized

    /* make sure all fd_install() have seen resize_in_progress
     * or have finished their rcu_read_lock_sched() section.
     */
    if (atomic_read(&files->count) > 1)
        synchronize_rcu();

    spin_lock(&files->file_lock);
    if (!new_fdt)
        return -ENOMEM;
    /*
     * extremely unlikely race - sysctl_nr_open decreased between the check in
     * caller and alloc_fdtable().  Cheaper to catch it here...
     */
    if (unlikely(new_fdt->max_fds <= nr)) {
        __my_free_fdtable(new_fdt);
        return -EMFILE;
    }
    cur_fdt = files_fdtable(files);
    BUG_ON(nr < cur_fdt->max_fds);
    my_copy_fdtable(new_fdt, cur_fdt); // copy_fdtable customized
    rcu_assign_pointer(files->fdt, new_fdt);
    if (cur_fdt != &files->fdtab)
        call_rcu(&cur_fdt->rcu, my_free_fdtable_rcu);
    /* coupled with smp_rmb() in fd_install() */
    smp_wmb();
    return 1;
}

static int my_expand_files(struct files_struct *files, unsigned int nr)
    __releases(files->file_lock)
    __acquires(files->file_lock)
{
    struct fdtable *fdt;
    int expanded = 0;

repeat:
    fdt = files_fdtable(files);

    /* Do we need to expand? */
    if (nr < fdt->max_fds)
        return expanded;

    /* Can we expand? */
    if (nr >= sysctl_nr_open)
        return -EMFILE;

    if (unlikely(files->resize_in_progress)) {
        spin_unlock(&files->file_lock);
        expanded = 1;
        wait_event(files->resize_wait, !files->resize_in_progress);
        spin_lock(&files->file_lock);
        goto repeat;
    }

    /* All good, so we try */
    files->resize_in_progress = true;
    expanded = my_expand_fdtable(files, nr);
    files->resize_in_progress = false;

    wake_up_all(&files->resize_wait);
    return expanded;
}

int my_alloc_fd(unsigned start, unsigned end, unsigned flags)
{
    // printk("BITBIT_SIZE(64)= %ld", BITBIT_SIZE(64));
    // printk("L1_CACHE_BYTES= %d", L1_CACHE_BYTES);
    printk("[%s]: my_alloc_fd start", __func__);
    struct files_struct *files = current->files;
	unsigned int fd;
	int error;
	struct fdtable *fdt;

    spin_lock(&files->file_lock);
repeat:
	fdt = files_fdtable(files);
	fd = start;
    printk("[%s]: fd(start): %d\n", __func__, fd);
	
    if (fd < files->next_fd)
		fd = files->next_fd;
        printk("[%s]: fd(files->next_fd): %d\n", __func__, fd);
	if (fd < fdt->max_fds)
		fd = my_find_next_fd(fdt, fd); // checks all fds at the bit level, and return the first encountered unallocated fd
        printk("[%s]: fd: %d\n", __func__, fd);
	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	error = -EMFILE;
	if (fd >= end)
		goto out;

	error = my_expand_files(files, fd);
	printk("[%s]: error returned from expand_files(): %d\n", __func__, error); // test code
    if (error < 0)
		goto out;

	/*
	 * If we needed to expand the fs array we
	 * might have blocked - try again.
	 */
	if (error)
		goto repeat;

	if (start <= files->next_fd)
		files->next_fd = fd + 1;

	__my_set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	error = fd;
#if 1
	/* Sanity check */
	if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	printk("[%s]: final error value(return value): %d", __func__, error); // test code
    return error;
}

int __my_get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
	return my_alloc_fd(0, nofile, flags);
}

int my_get_unused_fd_flags(unsigned flags)
{
    printk("[%s]: __get_unused_fd_flags function executed", __func__);
    return __my_get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE));
}
EXPORT_SYMBOL(my_get_unused_fd_flags);
