// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/pxt4/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  pxt4 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/pagevec.h>
#include <linux/uio.h>
#include <linux/mman.h>
#include <linux/backing-dev.h>
#include "pxt4.h"
#include "pxt4_jbd3.h"
#include "xattr.h"
#include "acl.h"
#include "truncate.h"

/*
 * Returns %true if the given DIO request should be attempted with DIO, or
 * %false if it should fall back to buffered I/O.
 *
 * DIO isn't well specified; when it's unsupported (either due to the request
 * being misaligned, or due to the file not supporting DIO at all), filesystems
 * either fall back to buffered I/O or return EINVAL.  For files that don't use
 * any special features like encryption or verity, pxt4 has traditionally
 * returned EINVAL for misaligned DIO.  iomap_dio_rw() uses this convention too.
 * In this case, we should attempt the DIO, *not* fall back to buffered I/O.
 *
 * In contrast, in cases where DIO is unsupported due to pxt4 features, pxt4
 * traditionally falls back to buffered I/O.
 *
 * This function implements the traditional pxt4 behavior in all these cases.
 */
static bool pxt4_should_use_dio(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	u32 dio_align = pxt4_dio_alignment(inode);

	if (dio_align == 0)
		return false;

	if (dio_align == 1)
		return true;

	return IS_ALIGNED(iocb->ki_pos | iov_iter_alignment(iter), dio_align);
}

static ssize_t pxt4_dio_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock_shared(inode))
			return -EAGAIN;
	} else {
		inode_lock_shared(inode);
	}

	if (!pxt4_should_use_dio(iocb, to)) {
		inode_unlock_shared(inode);
		/*
		 * Fallback to buffered I/O if the operation being performed on
		 * the inode is not supported by direct I/O. The IOCB_DIRECT
		 * flag needs to be cleared here in order to ensure that the
		 * direct I/O path within generic_file_read_iter() is not
		 * taken.
		 */
		iocb->ki_flags &= ~IOCB_DIRECT;
		return generic_file_read_iter(iocb, to);
	}

	ret = iomap_dio_rw(iocb, to, &pxt4_iomap_ops, NULL, 0, NULL, 0);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}

#ifdef CONFIG_FS_DAX
static ssize_t pxt4_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock_shared(inode))
			return -EAGAIN;
	} else {
		inode_lock_shared(inode);
	}
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		inode_unlock_shared(inode);
		/* Fallback to buffered IO in case we cannot support DAX */
		return generic_file_read_iter(iocb, to);
	}
	ret = dax_iomap_rw(iocb, to, &pxt4_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif

static ssize_t pxt4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	if (unlikely(pxt4_forced_shutdown(inode->i_sb)))
		return -EIO;

	if (!iov_iter_count(to))
		return 0; /* skip atime */

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return pxt4_dax_read_iter(iocb, to);
#endif
	if (iocb->ki_flags & IOCB_DIRECT)
		return pxt4_dio_read_iter(iocb, to);

	return generic_file_read_iter(iocb, to);
}

static ssize_t pxt4_file_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len, unsigned int flags)
{
	struct inode *inode = file_inode(in);

	if (unlikely(pxt4_forced_shutdown(inode->i_sb)))
		return -EIO;
	return filemap_splice_read(in, ppos, pipe, len, flags);
}

/*
 * Called when an inode is released. Note that this is different
 * from pxt4_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int pxt4_release_file(struct inode *inode, struct file *filp)
{
	if (pxt4_test_inode_state(inode, PXT4_STATE_DA_ALLOC_CLOSE)) {
		pxt4_alloc_da_blocks(inode);
		pxt4_clear_inode_state(inode, PXT4_STATE_DA_ALLOC_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
			(atomic_read(&inode->i_writecount) == 1) &&
			!PXT4_I(inode)->i_reserved_data_blocks) {
		down_write(&PXT4_I(inode)->i_data_sem);
		pxt4_discard_preallocations(inode, 0);
		up_write(&PXT4_I(inode)->i_data_sem);
	}
	if (is_dx(inode) && filp->private_data)
		pxt4_htree_free_dir_info(filp->private_data);

	return 0;
}

/*
 * This tests whether the IO in question is block-aligned or not.
 * Ext4 utilizes unwritten extents when hole-filling during direct IO, and they
 * are converted to written only after the IO is complete.  Until they are
 * mapped, these blocks appear as holes, so dio_zero_block() will assume that
 * it needs to zero out portions of the start and/or end block.  If 2 AIO
 * threads are at work on the same unwritten block, they must be synchronized
 * or one thread will zero the other's data, causing corruption.
 */
static bool
pxt4_unaligned_io(struct inode *inode, struct iov_iter *from, loff_t pos)
{
	struct super_block *sb = inode->i_sb;
	unsigned long blockmask = sb->s_blocksize - 1;

	if ((pos | iov_iter_alignment(from)) & blockmask)
		return true;

	return false;
}

static bool
pxt4_extending_io(struct inode *inode, loff_t offset, size_t len)
{
	if (offset + len > i_size_read(inode) ||
	    offset + len > PXT4_I(inode)->i_disksize)
		return true;
	return false;
}

/* Is IO overwriting allocated or initialized blocks? */
static bool pxt4_overwrite_io(struct inode *inode,
			      loff_t pos, loff_t len, bool *unwritten)
{
	struct pxt4_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	int err, blklen;

	if (pos + len > i_size_read(inode))
		return false;

	map.m_lblk = pos >> blkbits;
	map.m_len = PXT4_MAX_BLOCKS(len, pos, blkbits);
	blklen = map.m_len;

	err = pxt4_map_blocks(NULL, inode, &map, 0);
	if (err != blklen)
		return false;
	/*
	 * 'err==len' means that all of the blocks have been preallocated,
	 * regardless of whether they have been initialized or not. We need to
	 * check m_flags to distinguish the unwritten extents.
	 */
	*unwritten = !(map.m_flags & PXT4_MAP_MAPPED);
	return true;
}

static ssize_t pxt4_generic_write_checks(struct kiocb *iocb,
					 struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (unlikely(IS_IMMUTABLE(inode)))
		return -EPERM;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		return ret;

	/*
	 * If we have encountered a bitmap-format file, the size limit
	 * is smaller than s_maxbytes, which is for extent-mapped files.
	 */
	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS))) {
		struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);

		if (iocb->ki_pos >= sbi->s_bitmap_maxbytes)
			return -EFBIG;
		iov_iter_truncate(from, sbi->s_bitmap_maxbytes - iocb->ki_pos);
	}

	return iov_iter_count(from);
}

static ssize_t pxt4_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret, count;

	count = pxt4_generic_write_checks(iocb, from);
	if (count <= 0)
		return count;

	ret = file_modified(iocb->ki_filp);
	if (ret)
		return ret;
	return count;
}

static ssize_t pxt4_buffered_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT)
		return -EOPNOTSUPP;

	inode_lock(inode);
	ret = pxt4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	ret = generic_perform_write(iocb, from);

out:
	inode_unlock(inode);
	if (unlikely(ret <= 0))
		return ret;
	return generic_write_sync(iocb, ret);
}

static ssize_t pxt4_handle_inode_extension(struct inode *inode, loff_t offset,
					   ssize_t count)
{
	handle_t *handle;

	lockdep_assert_held_write(&inode->i_rwsem);
	handle = pxt4_journal_start(inode, PXT4_HT_INODE, 2);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (pxt4_update_inode_size(inode, offset + count)) {
		int ret = pxt4_mark_inode_dirty(handle, inode);
		if (unlikely(ret)) {
			pxt4_journal_stop(handle);
			return ret;
		}
	}

	if (inode->i_nlink)
		pxt4_orphan_del(handle, inode);
	pxt4_journal_stop(handle);

	return count;
}

/*
 * Clean up the inode after DIO or DAX extending write has completed and the
 * inode size has been updated using pxt4_handle_inode_extension().
 */
static void pxt4_inode_extension_cleanup(struct inode *inode, ssize_t count)
{
	lockdep_assert_held_write(&inode->i_rwsem);
	if (count < 0) {
		pxt4_truncate_failed_write(inode);
		/*
		 * If the truncate operation failed early, then the inode may
		 * still be on the orphan list. In that case, we need to try
		 * remove the inode from the in-memory linked list.
		 */
		if (inode->i_nlink)
			pxt4_orphan_del(NULL, inode);
		return;
	}
	/*
	 * If i_disksize got extended either due to writeback of delalloc
	 * blocks or extending truncate while the DIO was running we could fail
	 * to cleanup the orphan list in pxt4_handle_inode_extension(). Do it
	 * now.
	 */
	if (!list_empty(&PXT4_I(inode)->i_orphan) && inode->i_nlink) {
		handle_t *handle = pxt4_journal_start(inode, PXT4_HT_INODE, 2);

		if (IS_ERR(handle)) {
			/*
			 * The write has successfully completed. Not much to
			 * do with the error here so just cleanup the orphan
			 * list and hope for the best.
			 */
			pxt4_orphan_del(NULL, inode);
			return;
		}
		pxt4_orphan_del(handle, inode);
		pxt4_journal_stop(handle);
	}
}

static int pxt4_dio_write_end_io(struct kiocb *iocb, ssize_t size,
				 int error, unsigned int flags)
{
	loff_t pos = iocb->ki_pos;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (!error && size && flags & IOMAP_DIO_UNWRITTEN)
		error = pxt4_convert_unwritten_extents(NULL, inode, pos, size);
	if (error)
		return error;
	/*
	 * Note that PXT4_I(inode)->i_disksize can get extended up to
	 * inode->i_size while the I/O was running due to writeback of delalloc
	 * blocks. But the code in pxt4_iomap_alloc() is careful to use
	 * zeroed/unwritten extents if this is possible; thus we won't leave
	 * uninitialized blocks in a file even if we didn't succeed in writing
	 * as much as we intended. Also we can race with truncate or write
	 * expanding the file so we have to be a bit careful here.
	 */
	if (pos + size <= READ_ONCE(PXT4_I(inode)->i_disksize) &&
	    pos + size <= i_size_read(inode))
		return size;
	return pxt4_handle_inode_extension(inode, pos, size);
}

static const struct iomap_dio_ops pxt4_dio_write_ops = {
	.end_io = pxt4_dio_write_end_io,
};

/*
 * The intention here is to start with shared lock acquired then see if any
 * condition requires an exclusive inode lock. If yes, then we restart the
 * whole operation by releasing the shared lock and acquiring exclusive lock.
 *
 * - For unaligned_io we never take shared lock as it may cause data corruption
 *   when two unaligned IO tries to modify the same block e.g. while zeroing.
 *
 * - For extending writes case we don't take the shared lock, since it requires
 *   updating inode i_disksize and/or orphan handling with exclusive lock.
 *
 * - shared locking will only be true mostly with overwrites, including
 *   initialized blocks and unwritten blocks. For overwrite unwritten blocks
 *   we protect splitting extents by i_data_sem in pxt4_inode_info, so we can
 *   also release exclusive i_rwsem lock.
 *
 * - Otherwise we will switch to exclusive i_rwsem lock.
 */
static ssize_t pxt4_dio_write_checks(struct kiocb *iocb, struct iov_iter *from,
				     bool *ilock_shared, bool *extend,
				     bool *unwritten, int *dio_flags)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	loff_t offset;
	size_t count;
	ssize_t ret;
	bool overwrite, unaligned_io;

restart:
	ret = pxt4_generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	offset = iocb->ki_pos;
	count = ret;

	unaligned_io = pxt4_unaligned_io(inode, from, offset);
	*extend = pxt4_extending_io(inode, offset, count);
	overwrite = pxt4_overwrite_io(inode, offset, count, unwritten);

	/*
	 * Determine whether we need to upgrade to an exclusive lock. This is
	 * required to change security info in file_modified(), for extending
	 * I/O, any form of non-overwrite I/O, and unaligned I/O to unwritten
	 * extents (as partial block zeroing may be required).
	 *
	 * Note that unaligned writes are allowed under shared lock so long as
	 * they are pure overwrites. Otherwise, concurrent unaligned writes risk
	 * data corruption due to partial block zeroing in the dio layer, and so
	 * the I/O must occur exclusively.
	 */
	if (*ilock_shared &&
	    ((!IS_NOSEC(inode) || *extend || !overwrite ||
	     (unaligned_io && *unwritten)))) {
		if (iocb->ki_flags & IOCB_NOWAIT) {
			ret = -EAGAIN;
			goto out;
		}
		inode_unlock_shared(inode);
		*ilock_shared = false;
		inode_lock(inode);
		goto restart;
	}

	/*
	 * Now that locking is settled, determine dio flags and exclusivity
	 * requirements. We don't use DIO_OVERWRITE_ONLY because we enforce
	 * behavior already. The inode lock is already held exclusive if the
	 * write is non-overwrite or extending, so drain all outstanding dio and
	 * set the force wait dio flag.
	 */
	if (!*ilock_shared && (unaligned_io || *extend)) {
		if (iocb->ki_flags & IOCB_NOWAIT) {
			ret = -EAGAIN;
			goto out;
		}
		if (unaligned_io && (!overwrite || *unwritten))
			inode_dio_wait(inode);
		*dio_flags = IOMAP_DIO_FORCE_WAIT;
	}

	ret = file_modified(file);
	if (ret < 0)
		goto out;

	return count;
out:
	if (*ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);
	return ret;
}

static ssize_t pxt4_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	handle_t *handle;
	struct inode *inode = file_inode(iocb->ki_filp);
	loff_t offset = iocb->ki_pos;
	size_t count = iov_iter_count(from);
	const struct iomap_ops *iomap_ops = &pxt4_iomap_ops;
	bool extend = false, unwritten = false;
	bool ilock_shared = true;
	int dio_flags = 0;

	/*
	 * Quick check here without any i_rwsem lock to see if it is extending
	 * IO. A more reliable check is done in pxt4_dio_write_checks() with
	 * proper locking in place.
	 */
	if (offset + count > i_size_read(inode))
		ilock_shared = false;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (ilock_shared) {
			if (!inode_trylock_shared(inode))
				return -EAGAIN;
		} else {
			if (!inode_trylock(inode))
				return -EAGAIN;
		}
	} else {
		if (ilock_shared)
			inode_lock_shared(inode);
		else
			inode_lock(inode);
	}

	/* Fallback to buffered I/O if the inode does not support direct I/O. */
	if (!pxt4_should_use_dio(iocb, from)) {
		if (ilock_shared)
			inode_unlock_shared(inode);
		else
			inode_unlock(inode);
		return pxt4_buffered_write_iter(iocb, from);
	}

	/*
	 * Prevent inline data from being created since we are going to allocate
	 * blocks for DIO. We know the inode does not currently have inline data
	 * because pxt4_should_use_dio() checked for it, but we have to clear
	 * the state flag before the write checks because a lock cycle could
	 * introduce races with other writers.
	 */
	pxt4_clear_inode_state(inode, PXT4_STATE_MAY_INLINE_DATA);

	ret = pxt4_dio_write_checks(iocb, from, &ilock_shared, &extend,
				    &unwritten, &dio_flags);
	if (ret <= 0)
		return ret;

	offset = iocb->ki_pos;
	count = ret;

	if (extend) {
		handle = pxt4_journal_start(inode, PXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}

		ret = pxt4_orphan_add(handle, inode);
		if (ret) {
			pxt4_journal_stop(handle);
			goto out;
		}

		pxt4_journal_stop(handle);
	}

	if (ilock_shared && !unwritten)
		iomap_ops = &pxt4_iomap_overwrite_ops;
	ret = iomap_dio_rw(iocb, from, iomap_ops, &pxt4_dio_write_ops,
			   dio_flags, NULL, 0);
	if (ret == -ENOTBLK)
		ret = 0;
	if (extend) {
		/*
		 * We always perform extending DIO write synchronously so by
		 * now the IO is completed and pxt4_handle_inode_extension()
		 * was called. Cleanup the inode in case of error or race with
		 * writeback of delalloc blocks.
		 */
		WARN_ON_ONCE(ret == -EIOCBQUEUED);
		pxt4_inode_extension_cleanup(inode, ret);
	}

out:
	if (ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);

	if (ret >= 0 && iov_iter_count(from)) {
		ssize_t err;
		loff_t endbyte;

		offset = iocb->ki_pos;
		err = pxt4_buffered_write_iter(iocb, from);
		if (err < 0)
			return err;

		/*
		 * We need to ensure that the pages within the page cache for
		 * the range covered by this I/O are written to disk and
		 * invalidated. This is in attempt to preserve the expected
		 * direct I/O semantics in the case we fallback to buffered I/O
		 * to complete off the I/O request.
		 */
		ret += err;
		endbyte = offset + err - 1;
		err = filemap_write_and_wait_range(iocb->ki_filp->f_mapping,
						   offset, endbyte);
		if (!err)
			invalidate_mapping_pages(iocb->ki_filp->f_mapping,
						 offset >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);
	}

	return ret;
}

#ifdef CONFIG_FS_DAX
static ssize_t
pxt4_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	size_t count;
	loff_t offset;
	handle_t *handle;
	bool extend = false;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(inode))
			return -EAGAIN;
	} else {
		inode_lock(inode);
	}

	ret = pxt4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	offset = iocb->ki_pos;
	count = iov_iter_count(from);

	if (offset + count > PXT4_I(inode)->i_disksize) {
		handle = pxt4_journal_start(inode, PXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}

		ret = pxt4_orphan_add(handle, inode);
		if (ret) {
			pxt4_journal_stop(handle);
			goto out;
		}

		extend = true;
		pxt4_journal_stop(handle);
	}

	ret = dax_iomap_rw(iocb, from, &pxt4_iomap_ops);

	if (extend) {
		ret = pxt4_handle_inode_extension(inode, offset, ret);
		pxt4_inode_extension_cleanup(inode, ret);
	}
out:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}
#endif

static ssize_t
pxt4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	if (unlikely(pxt4_forced_shutdown(inode->i_sb)))
		return -EIO;

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return pxt4_dax_write_iter(iocb, from);
#endif
	if (iocb->ki_flags & IOCB_DIRECT)
		return pxt4_dio_write_iter(iocb, from);
	else
		return pxt4_buffered_write_iter(iocb, from);
}

#ifdef CONFIG_FS_DAX
static vm_fault_t pxt4_dax_huge_fault(struct vm_fault *vmf, unsigned int order)
{
	int error = 0;
	vm_fault_t result;
	int retries = 0;
	handle_t *handle = NULL;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;

	/*
	 * We have to distinguish real writes from writes which will result in a
	 * COW page; COW writes should *not* poke the journal (the file will not
	 * be changed). Doing so would cause unintended failures when mounted
	 * read-only.
	 *
	 * We check for VM_SHARED rather than vmf->cow_page since the latter is
	 * unset for order != 0 (i.e. only in do_cow_fault); for
	 * other sizes, dax_iomap_fault will handle splitting / fallback so that
	 * we eventually come back with a COW page.
	 */
	bool write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pfn_t pfn;

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
		filemap_invalidate_lock_shared(mapping);
retry:
		handle = pxt4_journal_start_sb(sb, PXT4_HT_WRITE_PAGE,
					       PXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle)) {
			filemap_invalidate_unlock_shared(mapping);
			sb_end_pagefault(sb);
			return VM_FAULT_SIGBUS;
		}
	} else {
		filemap_invalidate_lock_shared(mapping);
	}
	result = dax_iomap_fault(vmf, order, &pfn, &error, &pxt4_iomap_ops);
	if (write) {
		pxt4_journal_stop(handle);

		if ((result & VM_FAULT_ERROR) && error == -ENOSPC &&
		    pxt4_should_retry_alloc(sb, &retries))
			goto retry;
		/* Handling synchronous page fault? */
		if (result & VM_FAULT_NEEDDSYNC)
			result = dax_finish_sync_fault(vmf, order, pfn);
		filemap_invalidate_unlock_shared(mapping);
		sb_end_pagefault(sb);
	} else {
		filemap_invalidate_unlock_shared(mapping);
	}

	return result;
}

static vm_fault_t pxt4_dax_fault(struct vm_fault *vmf)
{
	return pxt4_dax_huge_fault(vmf, 0);
}

static const struct vm_operations_struct pxt4_dax_vm_ops = {
	.fault		= pxt4_dax_fault,
	.huge_fault	= pxt4_dax_huge_fault,
	.page_mkwrite	= pxt4_dax_fault,
	.pfn_mkwrite	= pxt4_dax_fault,
};
#else
#define pxt4_dax_vm_ops	pxt4_file_vm_ops
#endif

static const struct vm_operations_struct pxt4_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = pxt4_page_mkwrite,
};

static int pxt4_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;
	struct dax_device *dax_dev = PXT4_SB(inode->i_sb)->s_daxdev;

	if (unlikely(pxt4_forced_shutdown(inode->i_sb)))
		return -EIO;

	/*
	 * We don't support synchronous mappings for non-DAX files and
	 * for DAX files if underneath dax_device is not synchronous.
	 */
	if (!daxdev_mapping_supported(vma, dax_dev))
		return -EOPNOTSUPP;

	file_accessed(file);
	if (IS_DAX(file_inode(file))) {
		vma->vm_ops = &pxt4_dax_vm_ops;
		vm_flags_set(vma, VM_HUGEPAGE);
	} else {
		vma->vm_ops = &pxt4_file_vm_ops;
	}
	return 0;
}

static int pxt4_sample_last_mounted(struct super_block *sb,
				    struct vfsmount *mnt)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct path path;
	char buf[64], *cp;
	handle_t *handle;
	int err;

	if (likely(pxt4_test_mount_flag(sb, PXT4_MF_MNTDIR_SAMPLED)))
		return 0;

	if (sb_rdonly(sb) || !sb_start_intwrite_trylock(sb))
		return 0;

	pxt4_set_mount_flag(sb, PXT4_MF_MNTDIR_SAMPLED);
	/*
	 * Sample where the filesystem has been mounted and
	 * store it in the superblock for sysadmin convenience
	 * when trying to sort through large numbers of block
	 * devices or filesystem images.
	 */
	memset(buf, 0, sizeof(buf));
	path.mnt = mnt;
	path.dentry = mnt->mnt_root;
	cp = d_path(&path, buf, sizeof(buf));
	err = 0;
	if (IS_ERR(cp))
		goto out;

	handle = pxt4_journal_start_sb(sb, PXT4_HT_MISC, 1);
	err = PTR_ERR(handle);
	if (IS_ERR(handle))
		goto out;
	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = pxt4_journal_get_write_access(handle, sb, sbi->s_sbh,
					    PXT4_JTR_NONE);
	if (err)
		goto out_journal;
	lock_buffer(sbi->s_sbh);
	strncpy(sbi->s_es->s_last_mounted, cp,
		sizeof(sbi->s_es->s_last_mounted));
	pxt4_superblock_csum_set(sb);
	unlock_buffer(sbi->s_sbh);
	pxt4_handle_dirty_metadata(handle, NULL, sbi->s_sbh);
out_journal:
	pxt4_journal_stop(handle);
out:
	sb_end_intwrite(sb);
	return err;
}

static int pxt4_file_open(struct inode *inode, struct file *filp)
{
	int ret;

	if (unlikely(pxt4_forced_shutdown(inode->i_sb)))
		return -EIO;

	ret = pxt4_sample_last_mounted(inode->i_sb, filp->f_path.mnt);
	if (ret)
		return ret;

	ret = fscrypt_file_open(inode, filp);
	if (ret)
		return ret;

	ret = fsverity_file_open(inode, filp);
	if (ret)
		return ret;

	/*
	 * Set up the jbd3_inode if we are opening the inode for
	 * writing and the journal is present
	 */
	if (filp->f_mode & FMODE_WRITE) {
		ret = pxt4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}

	filp->f_mode |= FMODE_NOWAIT | FMODE_BUF_RASYNC |
			FMODE_DIO_PARALLEL_WRITE;
	return dquot_file_open(inode, filp);
}

/*
 * pxt4_llseek() handles both block-mapped and extent-mapped maxbytes values
 * by calling generic_file_llseek_size() with the appropriate maxbytes
 * value for each.
 */
loff_t pxt4_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes;

	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)))
		maxbytes = PXT4_SB(inode->i_sb)->s_bitmap_maxbytes;
	else
		maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	default:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_HOLE:
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset,
					 &pxt4_iomap_report_ops);
		inode_unlock_shared(inode);
		break;
	case SEEK_DATA:
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset,
					 &pxt4_iomap_report_ops);
		inode_unlock_shared(inode);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, maxbytes);
}

const struct file_operations pxt4_file_operations = {
	.llseek		= pxt4_llseek,
	.read_iter	= pxt4_file_read_iter,
	.write_iter	= pxt4_file_write_iter,
	.iopoll		= iocb_bio_iopoll,
	.unlocked_ioctl = pxt4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= pxt4_compat_ioctl,
#endif
	.mmap		= pxt4_file_mmap,
	.mmap_supported_flags = MAP_SYNC,
	.open		= pxt4_file_open,
	.release	= pxt4_release_file,
	.fsync		= pxt4_sync_file,
	.get_unmapped_area = thp_get_unmapped_area,
	.splice_read	= pxt4_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= pxt4_fallocate,
};

const struct inode_operations pxt4_file_inode_operations = {
	.setattr	= pxt4_setattr,
	.getattr	= pxt4_file_getattr,
	.listxattr	= pxt4_listxattr,
	.get_inode_acl	= pxt4_get_acl,
	.set_acl	= pxt4_set_acl,
	.fiemap		= pxt4_fiemap,
	.fileattr_get	= pxt4_fileattr_get,
	.fileattr_set	= pxt4_fileattr_set,
};
EXPORT_SYMBOL(pxt4_file_inode_operations); // open_syscall_module
