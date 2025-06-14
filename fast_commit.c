// SPDX-License-Identifier: GPL-2.0

/*
 * fs/pxt4/fast_commit.c
 *
 * Written by Harshad Shirwadkar <harshadshirwadkar@gmail.com>
 *
 * Ext4 fast commits routines.
 */
#include "pxt4.h"
#include "pxt4_jbd3.h"
#include "pxt4_extents.h"
#include "mballoc.h"

/*
 * Ext4 Fast Commits
 * -----------------
 *
 * Ext4 fast commits implement fine grained journalling for Ext4.
 *
 * Fast commits are organized as a log of tag-length-value (TLV) structs. (See
 * struct pxt4_fc_tl). Each TLV contains some delta that is replayed TLV by
 * TLV during the recovery phase. For the scenarios for which we currently
 * don't have replay code, fast commit falls back to full commits.
 * Fast commits record delta in one of the following three categories.
 *
 * (A) Directory entry updates:
 *
 * - PXT4_FC_TAG_UNLINK		- records directory entry unlink
 * - PXT4_FC_TAG_LINK		- records directory entry link
 * - PXT4_FC_TAG_CREAT		- records inode and directory entry creation
 *
 * (B) File specific data range updates:
 *
 * - PXT4_FC_TAG_ADD_RANGE	- records addition of new blocks to an inode
 * - PXT4_FC_TAG_DEL_RANGE	- records deletion of blocks from an inode
 *
 * (C) Inode metadata (mtime / ctime etc):
 *
 * - PXT4_FC_TAG_INODE		- record the inode that should be replayed
 *				  during recovery. Note that iblocks field is
 *				  not replayed and instead derived during
 *				  replay.
 * Commit Operation
 * ----------------
 * With fast commits, we maintain all the directory entry operations in the
 * order in which they are issued in an in-memory queue. This queue is flushed
 * to disk during the commit operation. We also maintain a list of inodes
 * that need to be committed during a fast commit in another in memory queue of
 * inodes. During the commit operation, we commit in the following order:
 *
 * [1] Lock inodes for any further data updates by setting COMMITTING state
 * [2] Submit data buffers of all the inodes
 * [3] Wait for [2] to complete
 * [4] Commit all the directory entry updates in the fast commit space
 * [5] Commit all the changed inode structures
 * [6] Write tail tag (this tag ensures the atomicity, please read the following
 *     section for more details).
 * [7] Wait for [4], [5] and [6] to complete.
 *
 * All the inode updates must call pxt4_fc_start_update() before starting an
 * update. If such an ongoing update is present, fast commit waits for it to
 * complete. The completion of such an update is marked by
 * pxt4_fc_stop_update().
 *
 * Fast Commit Ineligibility
 * -------------------------
 *
 * Not all operations are supported by fast commits today (e.g extended
 * attributes). Fast commit ineligibility is marked by calling
 * pxt4_fc_mark_ineligible(): This makes next fast commit operation to fall back
 * to full commit.
 *
 * Atomicity of commits
 * --------------------
 * In order to guarantee atomicity during the commit operation, fast commit
 * uses "PXT4_FC_TAG_TAIL" tag that marks a fast commit as complete. Tail
 * tag contains CRC of the contents and TID of the transaction after which
 * this fast commit should be applied. Recovery code replays fast commit
 * logs only if there's at least 1 valid tail present. For every fast commit
 * operation, there is 1 tail. This means, we may end up with multiple tails
 * in the fast commit space. Here's an example:
 *
 * - Create a new file A and remove existing file B
 * - fsync()
 * - Append contents to file A
 * - Truncate file A
 * - fsync()
 *
 * The fast commit space at the end of above operations would look like this:
 *      [HEAD] [CREAT A] [UNLINK B] [TAIL] [ADD_RANGE A] [DEL_RANGE A] [TAIL]
 *             |<---  Fast Commit 1   --->|<---      Fast Commit 2     ---->|
 *
 * Replay code should thus check for all the valid tails in the FC area.
 *
 * Fast Commit Replay Idempotence
 * ------------------------------
 *
 * Fast commits tags are idempotent in nature provided the recovery code follows
 * certain rules. The guiding principle that the commit path follows while
 * committing is that it stores the result of a particular operation instead of
 * storing the procedure.
 *
 * Let's consider this rename operation: 'mv /a /b'. Let's assume dirent '/a'
 * was associated with inode 10. During fast commit, instead of storing this
 * operation as a procedure "rename a to b", we store the resulting file system
 * state as a "series" of outcomes:
 *
 * - Link dirent b to inode 10
 * - Unlink dirent a
 * - Inode <10> with valid refcount
 *
 * Now when recovery code runs, it needs "enforce" this state on the file
 * system. This is what guarantees idempotence of fast commit replay.
 *
 * Let's take an example of a procedure that is not idempotent and see how fast
 * commits make it idempotent. Consider following sequence of operations:
 *
 *     rm A;    mv B A;    read A
 *  (x)     (y)        (z)
 *
 * (x), (y) and (z) are the points at which we can crash. If we store this
 * sequence of operations as is then the replay is not idempotent. Let's say
 * while in replay, we crash at (z). During the second replay, file A (which was
 * actually created as a result of "mv B A" operation) would get deleted. Thus,
 * file named A would be absent when we try to read A. So, this sequence of
 * operations is not idempotent. However, as mentioned above, instead of storing
 * the procedure fast commits store the outcome of each procedure. Thus the fast
 * commit log for above procedure would be as follows:
 *
 * (Let's assume dirent A was linked to inode 10 and dirent B was linked to
 * inode 11 before the replay)
 *
 *    [Unlink A]   [Link A to inode 11]   [Unlink B]   [Inode 11]
 * (w)          (x)                    (y)          (z)
 *
 * If we crash at (z), we will have file A linked to inode 11. During the second
 * replay, we will remove file A (inode 11). But we will create it back and make
 * it point to inode 11. We won't find B, so we'll just skip that step. At this
 * point, the refcount for inode 11 is not reliable, but that gets fixed by the
 * replay of last inode 11 tag. Crashes at points (w), (x) and (y) get handled
 * similarly. Thus, by converting a non-idempotent procedure into a series of
 * idempotent outcomes, fast commits ensured idempotence during the replay.
 *
 * TODOs
 * -----
 *
 * 0) Fast commit replay path hardening: Fast commit replay code should use
 *    journal handles to make sure all the updates it does during the replay
 *    path are atomic. With that if we crash during fast commit replay, after
 *    trying to do recovery again, we will find a file system where fast commit
 *    area is invalid (because new full commit would be found). In order to deal
 *    with that, fast commit replay code should ensure that the "FC_REPLAY"
 *    superblock state is persisted before starting the replay, so that after
 *    the crash, fast commit recovery code can look at that flag and perform
 *    fast commit recovery even if that area is invalidated by later full
 *    commits.
 *
 * 1) Fast commit's commit path locks the entire file system during fast
 *    commit. This has significant performance penalty. Instead of that, we
 *    should use pxt4_fc_start/stop_update functions to start inode level
 *    updates from pxt4_journal_start/stop. Once we do that we can drop file
 *    system locking during commit path.
 *
 * 2) Handle more ineligible cases.
 */

#include <trace/events/pxt4.h>
static struct kmem_cache *pxt4_fc_dentry_cachep;

static void pxt4_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	BUFFER_TRACE(bh, "");
	if (uptodate) {
		pxt4_debug("%s: Block %lld up-to-date",
			   __func__, bh->b_blocknr);
		set_buffer_uptodate(bh);
	} else {
		pxt4_debug("%s: Block %lld not up-to-date",
			   __func__, bh->b_blocknr);
		clear_buffer_uptodate(bh);
	}

	unlock_buffer(bh);
}

static inline void pxt4_fc_reset_inode(struct inode *inode)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);

	ei->i_fc_lblk_start = 0;
	ei->i_fc_lblk_len = 0;
}

void pxt4_fc_init_inode(struct inode *inode)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);

	pxt4_fc_reset_inode(inode);
	pxt4_clear_inode_state(inode, PXT4_STATE_FC_COMMITTING);
	INIT_LIST_HEAD(&ei->i_fc_list);
	INIT_LIST_HEAD(&ei->i_fc_dilist);
	init_waitqueue_head(&ei->i_fc_wait);
	atomic_set(&ei->i_fc_updates, 0);
}

/* This function must be called with sbi->s_fc_lock held. */
static void pxt4_fc_wait_committing_inode(struct inode *inode)
__releases(&PXT4_SB(inode->i_sb)->s_fc_lock)
{
	wait_queue_head_t *wq;
	struct pxt4_inode_info *ei = PXT4_I(inode);

#if (BITS_PER_LONG < 64)
	DEFINE_WAIT_BIT(wait, &ei->i_state_flags,
			PXT4_STATE_FC_COMMITTING);
	wq = bit_waitqueue(&ei->i_state_flags,
				PXT4_STATE_FC_COMMITTING);
#else
	DEFINE_WAIT_BIT(wait, &ei->i_flags,
			PXT4_STATE_FC_COMMITTING);
	wq = bit_waitqueue(&ei->i_flags,
				PXT4_STATE_FC_COMMITTING);
#endif
	lockdep_assert_held(&PXT4_SB(inode->i_sb)->s_fc_lock);
	prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
	spin_unlock(&PXT4_SB(inode->i_sb)->s_fc_lock);
	schedule();
	finish_wait(wq, &wait.wq_entry);
}

static bool pxt4_fc_disabled(struct super_block *sb)
{
	return (!test_opt2(sb, JOURNAL_FAST_COMMIT) ||
		(PXT4_SB(sb)->s_mount_state & PXT4_FC_REPLAY));
}

/*
 * Inform Ext4's fast about start of an inode update
 *
 * This function is called by the high level call VFS callbacks before
 * performing any inode update. This function blocks if there's an ongoing
 * fast commit on the inode in question.
 */
void pxt4_fc_start_update(struct inode *inode)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);

	if (pxt4_fc_disabled(inode->i_sb))
		return;

restart:
	spin_lock(&PXT4_SB(inode->i_sb)->s_fc_lock);
	if (list_empty(&ei->i_fc_list))
		goto out;

	if (pxt4_test_inode_state(inode, PXT4_STATE_FC_COMMITTING)) {
		pxt4_fc_wait_committing_inode(inode);
		goto restart;
	}
out:
	atomic_inc(&ei->i_fc_updates);
	spin_unlock(&PXT4_SB(inode->i_sb)->s_fc_lock);
}

/*
 * Stop inode update and wake up waiting fast commits if any.
 */
void pxt4_fc_stop_update(struct inode *inode)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);

	if (pxt4_fc_disabled(inode->i_sb))
		return;

	if (atomic_dec_and_test(&ei->i_fc_updates))
		wake_up_all(&ei->i_fc_wait);
}

/*
 * Remove inode from fast commit list. If the inode is being committed
 * we wait until inode commit is done.
 */
void pxt4_fc_del(struct inode *inode)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	struct pxt4_fc_dentry_update *fc_dentry;

	if (pxt4_fc_disabled(inode->i_sb))
		return;

restart:
	spin_lock(&PXT4_SB(inode->i_sb)->s_fc_lock);
	if (list_empty(&ei->i_fc_list) && list_empty(&ei->i_fc_dilist)) {
		spin_unlock(&PXT4_SB(inode->i_sb)->s_fc_lock);
		return;
	}

	if (pxt4_test_inode_state(inode, PXT4_STATE_FC_COMMITTING)) {
		pxt4_fc_wait_committing_inode(inode);
		goto restart;
	}

	if (!list_empty(&ei->i_fc_list))
		list_del_init(&ei->i_fc_list);

	/*
	 * Since this inode is getting removed, let's also remove all FC
	 * dentry create references, since it is not needed to log it anyways.
	 */
	if (list_empty(&ei->i_fc_dilist)) {
		spin_unlock(&sbi->s_fc_lock);
		return;
	}

	fc_dentry = list_first_entry(&ei->i_fc_dilist, struct pxt4_fc_dentry_update, fcd_dilist);
	WARN_ON(fc_dentry->fcd_op != PXT4_FC_TAG_CREAT);
	list_del_init(&fc_dentry->fcd_list);
	list_del_init(&fc_dentry->fcd_dilist);

	WARN_ON(!list_empty(&ei->i_fc_dilist));
	spin_unlock(&sbi->s_fc_lock);

	if (fc_dentry->fcd_name.name &&
		fc_dentry->fcd_name.len > DNAME_INLINE_LEN)
		kfree(fc_dentry->fcd_name.name);
	kmem_cache_free(pxt4_fc_dentry_cachep, fc_dentry);

	return;
}

/*
 * Mark file system as fast commit ineligible, and record latest
 * ineligible transaction tid. This means until the recorded
 * transaction, commit operation would result in a full jbd3 commit.
 */
void pxt4_fc_mark_ineligible(struct super_block *sb, int reason, handle_t *handle)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	tid_t tid;

	if (pxt4_fc_disabled(sb))
		return;

	pxt4_set_mount_flag(sb, PXT4_MF_FC_INELIGIBLE);
	if (handle && !IS_ERR(handle))
		tid = handle->h_transaction->t_tid;
	else {
		read_lock(&sbi->s_journal->j_state_lock);
		tid = sbi->s_journal->j_running_transaction ?
				sbi->s_journal->j_running_transaction->t_tid : 0;
		read_unlock(&sbi->s_journal->j_state_lock);
	}
	spin_lock(&sbi->s_fc_lock);
	if (sbi->s_fc_ineligible_tid < tid)
		sbi->s_fc_ineligible_tid = tid;
	spin_unlock(&sbi->s_fc_lock);
	WARN_ON(reason >= PXT4_FC_REASON_MAX);
	sbi->s_fc_stats.fc_ineligible_reason_count[reason]++;
}

/*
 * Generic fast commit tracking function. If this is the first time this we are
 * called after a full commit, we initialize fast commit fields and then call
 * __fc_track_fn() with update = 0. If we have already been called after a full
 * commit, we pass update = 1. Based on that, the track function can determine
 * if it needs to track a field for the first time or if it needs to just
 * update the previously tracked value.
 *
 * If enqueue is set, this function enqueues the inode in fast commit list.
 */
static int pxt4_fc_track_template(
	handle_t *handle, struct inode *inode,
	int (*__fc_track_fn)(struct inode *, void *, bool),
	void *args, int enqueue)
{
	bool update = false;
	struct pxt4_inode_info *ei = PXT4_I(inode);
	struct pxt4_sb_info *sbi = PXT4_SB(inode->i_sb);
	tid_t tid = 0;
	int ret;

	tid = handle->h_transaction->t_tid;
	mutex_lock(&ei->i_fc_lock);
	if (tid == ei->i_sync_tid) {
		update = true;
	} else {
		pxt4_fc_reset_inode(inode);
		ei->i_sync_tid = tid;
	}
	ret = __fc_track_fn(inode, args, update);
	mutex_unlock(&ei->i_fc_lock);

	if (!enqueue)
		return ret;

	spin_lock(&sbi->s_fc_lock);
	if (list_empty(&PXT4_I(inode)->i_fc_list))
		list_add_tail(&PXT4_I(inode)->i_fc_list,
				(sbi->s_journal->j_flags & JBD3_FULL_COMMIT_ONGOING ||
				 sbi->s_journal->j_flags & JBD3_FAST_COMMIT_ONGOING) ?
				&sbi->s_fc_q[FC_Q_STAGING] :
				&sbi->s_fc_q[FC_Q_MAIN]);
	spin_unlock(&sbi->s_fc_lock);

	return ret;
}

struct __track_dentry_update_args {
	struct dentry *dentry;
	int op;
};

/* __track_fn for directory entry updates. Called with ei->i_fc_lock. */
static int __track_dentry_update(struct inode *inode, void *arg, bool update)
{
	struct pxt4_fc_dentry_update *node;
	struct pxt4_inode_info *ei = PXT4_I(inode);
	struct __track_dentry_update_args *dentry_update =
		(struct __track_dentry_update_args *)arg;
	struct dentry *dentry = dentry_update->dentry;
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = inode->i_sb;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	mutex_unlock(&ei->i_fc_lock);

	if (IS_ENCRYPTED(dir)) {
		pxt4_fc_mark_ineligible(sb, PXT4_FC_REASON_ENCRYPTED_FILENAME,
					NULL);
		mutex_lock(&ei->i_fc_lock);
		return -EOPNOTSUPP;
	}

	node = kmem_cache_alloc(pxt4_fc_dentry_cachep, GFP_NOFS);
	if (!node) {
		pxt4_fc_mark_ineligible(sb, PXT4_FC_REASON_NOMEM, NULL);
		mutex_lock(&ei->i_fc_lock);
		return -ENOMEM;
	}

	node->fcd_op = dentry_update->op;
	node->fcd_parent = dir->i_ino;
	node->fcd_ino = inode->i_ino;
	if (dentry->d_name.len > DNAME_INLINE_LEN) {
		node->fcd_name.name = kmalloc(dentry->d_name.len, GFP_NOFS);
		if (!node->fcd_name.name) {
			kmem_cache_free(pxt4_fc_dentry_cachep, node);
			pxt4_fc_mark_ineligible(sb, PXT4_FC_REASON_NOMEM, NULL);
			mutex_lock(&ei->i_fc_lock);
			return -ENOMEM;
		}
		memcpy((u8 *)node->fcd_name.name, dentry->d_name.name,
			dentry->d_name.len);
	} else {
		memcpy(node->fcd_iname, dentry->d_name.name,
			dentry->d_name.len);
		node->fcd_name.name = node->fcd_iname;
	}
	node->fcd_name.len = dentry->d_name.len;
	INIT_LIST_HEAD(&node->fcd_dilist);
	spin_lock(&sbi->s_fc_lock);
	if (sbi->s_journal->j_flags & JBD3_FULL_COMMIT_ONGOING ||
		sbi->s_journal->j_flags & JBD3_FAST_COMMIT_ONGOING)
		list_add_tail(&node->fcd_list,
				&sbi->s_fc_dentry_q[FC_Q_STAGING]);
	else
		list_add_tail(&node->fcd_list, &sbi->s_fc_dentry_q[FC_Q_MAIN]);

	/*
	 * This helps us keep a track of all fc_dentry updates which is part of
	 * this pxt4 inode. So in case the inode is getting unlinked, before
	 * even we get a chance to fsync, we could remove all fc_dentry
	 * references while evicting the inode in pxt4_fc_del().
	 * Also with this, we don't need to loop over all the inodes in
	 * sbi->s_fc_q to get the corresponding inode in
	 * pxt4_fc_commit_dentry_updates().
	 */
	if (dentry_update->op == PXT4_FC_TAG_CREAT) {
		WARN_ON(!list_empty(&ei->i_fc_dilist));
		list_add_tail(&node->fcd_dilist, &ei->i_fc_dilist);
	}
	spin_unlock(&sbi->s_fc_lock);
	mutex_lock(&ei->i_fc_lock);

	return 0;
}

void __pxt4_fc_track_unlink(handle_t *handle,
		struct inode *inode, struct dentry *dentry)
{
	struct __track_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = PXT4_FC_TAG_UNLINK;

	ret = pxt4_fc_track_template(handle, inode, __track_dentry_update,
					(void *)&args, 0);
	trace_pxt4_fc_track_unlink(handle, inode, dentry, ret);
}

void pxt4_fc_track_unlink(handle_t *handle, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	if (pxt4_fc_disabled(inode->i_sb))
		return;

	if (pxt4_test_mount_flag(inode->i_sb, PXT4_MF_FC_INELIGIBLE))
		return;

	__pxt4_fc_track_unlink(handle, inode, dentry);
}

void __pxt4_fc_track_link(handle_t *handle,
	struct inode *inode, struct dentry *dentry)
{
	struct __track_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = PXT4_FC_TAG_LINK;

	ret = pxt4_fc_track_template(handle, inode, __track_dentry_update,
					(void *)&args, 0);
	trace_pxt4_fc_track_link(handle, inode, dentry, ret);
}

void pxt4_fc_track_link(handle_t *handle, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	if (pxt4_fc_disabled(inode->i_sb))
		return;

	if (pxt4_test_mount_flag(inode->i_sb, PXT4_MF_FC_INELIGIBLE))
		return;

	__pxt4_fc_track_link(handle, inode, dentry);
}

void __pxt4_fc_track_create(handle_t *handle, struct inode *inode,
			  struct dentry *dentry)
{
	struct __track_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = PXT4_FC_TAG_CREAT;

	ret = pxt4_fc_track_template(handle, inode, __track_dentry_update,
					(void *)&args, 0);
	trace_pxt4_fc_track_create(handle, inode, dentry, ret);
}
EXPORT_SYMBOL(__pxt4_fc_track_create); // open_syscall_module

void pxt4_fc_track_create(handle_t *handle, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	if (pxt4_fc_disabled(inode->i_sb))
		return;

	if (pxt4_test_mount_flag(inode->i_sb, PXT4_MF_FC_INELIGIBLE))
		return;

	__pxt4_fc_track_create(handle, inode, dentry);
}
EXPORT_SYMBOL(pxt4_fc_track_create); // open_syscall_module

/* __track_fn for inode tracking */
static int __track_inode(struct inode *inode, void *arg, bool update)
{
	if (update)
		return -EEXIST;

	PXT4_I(inode)->i_fc_lblk_len = 0;

	return 0;
}

void pxt4_fc_track_inode(handle_t *handle, struct inode *inode)
{
	int ret;

	if (S_ISDIR(inode->i_mode))
		return;

	if (pxt4_fc_disabled(inode->i_sb))
		return;

	if (pxt4_should_journal_data(inode)) {
		pxt4_fc_mark_ineligible(inode->i_sb,
					PXT4_FC_REASON_INODE_JOURNAL_DATA, handle);
		return;
	}

	if (pxt4_test_mount_flag(inode->i_sb, PXT4_MF_FC_INELIGIBLE))
		return;

	ret = pxt4_fc_track_template(handle, inode, __track_inode, NULL, 1);
	trace_pxt4_fc_track_inode(handle, inode, ret);
}

struct __track_range_args {
	pxt4_lblk_t start, end;
};

/* __track_fn for tracking data updates */
static int __track_range(struct inode *inode, void *arg, bool update)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);
	pxt4_lblk_t oldstart;
	struct __track_range_args *__arg =
		(struct __track_range_args *)arg;

	if (inode->i_ino < PXT4_FIRST_INO(inode->i_sb)) {
		pxt4_debug("Special inode %ld being modified\n", inode->i_ino);
		return -ECANCELED;
	}

	oldstart = ei->i_fc_lblk_start;

	if (update && ei->i_fc_lblk_len > 0) {
		ei->i_fc_lblk_start = min(ei->i_fc_lblk_start, __arg->start);
		ei->i_fc_lblk_len =
			max(oldstart + ei->i_fc_lblk_len - 1, __arg->end) -
				ei->i_fc_lblk_start + 1;
	} else {
		ei->i_fc_lblk_start = __arg->start;
		ei->i_fc_lblk_len = __arg->end - __arg->start + 1;
	}

	return 0;
}

void pxt4_fc_track_range(handle_t *handle, struct inode *inode, pxt4_lblk_t start,
			 pxt4_lblk_t end)
{
	struct __track_range_args args;
	int ret;

	if (S_ISDIR(inode->i_mode))
		return;

	if (pxt4_fc_disabled(inode->i_sb))
		return;

	if (pxt4_test_mount_flag(inode->i_sb, PXT4_MF_FC_INELIGIBLE))
		return;

	args.start = start;
	args.end = end;

	ret = pxt4_fc_track_template(handle, inode,  __track_range, &args, 1);

	trace_pxt4_fc_track_range(handle, inode, start, end, ret);
}

static void pxt4_fc_submit_bh(struct super_block *sb, bool is_tail)
{
	blk_opf_t write_flags = REQ_SYNC;
	struct buffer_head *bh = PXT4_SB(sb)->s_fc_bh;

	/* Add REQ_FUA | REQ_PREFLUSH only its tail */
	if (test_opt(sb, BARRIER) && is_tail)
		write_flags |= REQ_FUA | REQ_PREFLUSH;
	lock_buffer(bh);
	set_buffer_dirty(bh);
	set_buffer_uptodate(bh);
	bh->b_end_io = pxt4_end_buffer_io_sync;
	submit_bh(REQ_OP_WRITE | write_flags, bh);
	PXT4_SB(sb)->s_fc_bh = NULL;
}

/* Ext4 commit path routines */

/*
 * Allocate len bytes on a fast commit buffer.
 *
 * During the commit time this function is used to manage fast commit
 * block space. We don't split a fast commit log onto different
 * blocks. So this function makes sure that if there's not enough space
 * on the current block, the remaining space in the current block is
 * marked as unused by adding PXT4_FC_TAG_PAD tag. In that case,
 * new block is from jbd3 and CRC is updated to reflect the padding
 * we added.
 */
static u8 *pxt4_fc_reserve_space(struct super_block *sb, int len, u32 *crc)
{
	struct pxt4_fc_tl tl;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct buffer_head *bh;
	int bsize = sbi->s_journal->j_blocksize;
	int ret, off = sbi->s_fc_bytes % bsize;
	int remaining;
	u8 *dst;

	/*
	 * If 'len' is too long to fit in any block alongside a PAD tlv, then we
	 * cannot fulfill the request.
	 */
	if (len > bsize - PXT4_FC_TAG_BASE_LEN)
		return NULL;

	if (!sbi->s_fc_bh) {
		ret = jbd3_fc_get_buf(PXT4_SB(sb)->s_journal, &bh);
		if (ret)
			return NULL;
		sbi->s_fc_bh = bh;
	}
	dst = sbi->s_fc_bh->b_data + off;

	/*
	 * Allocate the bytes in the current block if we can do so while still
	 * leaving enough space for a PAD tlv.
	 */
	remaining = bsize - PXT4_FC_TAG_BASE_LEN - off;
	if (len <= remaining) {
		sbi->s_fc_bytes += len;
		return dst;
	}

	/*
	 * Else, terminate the current block with a PAD tlv, then allocate a new
	 * block and allocate the bytes at the start of that new block.
	 */

	tl.fc_tag = cpu_to_le16(PXT4_FC_TAG_PAD);
	tl.fc_len = cpu_to_le16(remaining);
	memcpy(dst, &tl, PXT4_FC_TAG_BASE_LEN);
	memset(dst + PXT4_FC_TAG_BASE_LEN, 0, remaining);
	*crc = pxt4_chksum(sbi, *crc, sbi->s_fc_bh->b_data, bsize);

	pxt4_fc_submit_bh(sb, false);

	ret = jbd3_fc_get_buf(PXT4_SB(sb)->s_journal, &bh);
	if (ret)
		return NULL;
	sbi->s_fc_bh = bh;
	sbi->s_fc_bytes += bsize - off + len;
	return sbi->s_fc_bh->b_data;
}

/*
 * Complete a fast commit by writing tail tag.
 *
 * Writing tail tag marks the end of a fast commit. In order to guarantee
 * atomicity, after writing tail tag, even if there's space remaining
 * in the block, next commit shouldn't use it. That's why tail tag
 * has the length as that of the remaining space on the block.
 */
static int pxt4_fc_write_tail(struct super_block *sb, u32 crc)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_fc_tl tl;
	struct pxt4_fc_tail tail;
	int off, bsize = sbi->s_journal->j_blocksize;
	u8 *dst;

	/*
	 * pxt4_fc_reserve_space takes care of allocating an extra block if
	 * there's no enough space on this block for accommodating this tail.
	 */
	dst = pxt4_fc_reserve_space(sb, PXT4_FC_TAG_BASE_LEN + sizeof(tail), &crc);
	if (!dst)
		return -ENOSPC;

	off = sbi->s_fc_bytes % bsize;

	tl.fc_tag = cpu_to_le16(PXT4_FC_TAG_TAIL);
	tl.fc_len = cpu_to_le16(bsize - off + sizeof(struct pxt4_fc_tail));
	sbi->s_fc_bytes = round_up(sbi->s_fc_bytes, bsize);

	memcpy(dst, &tl, PXT4_FC_TAG_BASE_LEN);
	dst += PXT4_FC_TAG_BASE_LEN;
	tail.fc_tid = cpu_to_le32(sbi->s_journal->j_running_transaction->t_tid);
	memcpy(dst, &tail.fc_tid, sizeof(tail.fc_tid));
	dst += sizeof(tail.fc_tid);
	crc = pxt4_chksum(sbi, crc, sbi->s_fc_bh->b_data,
			  dst - (u8 *)sbi->s_fc_bh->b_data);
	tail.fc_crc = cpu_to_le32(crc);
	memcpy(dst, &tail.fc_crc, sizeof(tail.fc_crc));
	dst += sizeof(tail.fc_crc);
	memset(dst, 0, bsize - off); /* Don't leak uninitialized memory. */

	pxt4_fc_submit_bh(sb, true);

	return 0;
}

/*
 * Adds tag, length, value and updates CRC. Returns true if tlv was added.
 * Returns false if there's not enough space.
 */
static bool pxt4_fc_add_tlv(struct super_block *sb, u16 tag, u16 len, u8 *val,
			   u32 *crc)
{
	struct pxt4_fc_tl tl;
	u8 *dst;

	dst = pxt4_fc_reserve_space(sb, PXT4_FC_TAG_BASE_LEN + len, crc);
	if (!dst)
		return false;

	tl.fc_tag = cpu_to_le16(tag);
	tl.fc_len = cpu_to_le16(len);

	memcpy(dst, &tl, PXT4_FC_TAG_BASE_LEN);
	memcpy(dst + PXT4_FC_TAG_BASE_LEN, val, len);

	return true;
}

/* Same as above, but adds dentry tlv. */
static bool pxt4_fc_add_dentry_tlv(struct super_block *sb, u32 *crc,
				   struct pxt4_fc_dentry_update *fc_dentry)
{
	struct pxt4_fc_dentry_info fcd;
	struct pxt4_fc_tl tl;
	int dlen = fc_dentry->fcd_name.len;
	u8 *dst = pxt4_fc_reserve_space(sb,
			PXT4_FC_TAG_BASE_LEN + sizeof(fcd) + dlen, crc);

	if (!dst)
		return false;

	fcd.fc_parent_ino = cpu_to_le32(fc_dentry->fcd_parent);
	fcd.fc_ino = cpu_to_le32(fc_dentry->fcd_ino);
	tl.fc_tag = cpu_to_le16(fc_dentry->fcd_op);
	tl.fc_len = cpu_to_le16(sizeof(fcd) + dlen);
	memcpy(dst, &tl, PXT4_FC_TAG_BASE_LEN);
	dst += PXT4_FC_TAG_BASE_LEN;
	memcpy(dst, &fcd, sizeof(fcd));
	dst += sizeof(fcd);
	memcpy(dst, fc_dentry->fcd_name.name, dlen);

	return true;
}

/*
 * Writes inode in the fast commit space under TLV with tag @tag.
 * Returns 0 on success, error on failure.
 */
static int pxt4_fc_write_inode(struct inode *inode, u32 *crc)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);
	int inode_len = PXT4_GOOD_OLD_INODE_SIZE;
	int ret;
	struct pxt4_iloc iloc;
	struct pxt4_fc_inode fc_inode;
	struct pxt4_fc_tl tl;
	u8 *dst;

	ret = pxt4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	if (pxt4_test_inode_flag(inode, PXT4_INODE_INLINE_DATA))
		inode_len = PXT4_INODE_SIZE(inode->i_sb);
	else if (PXT4_INODE_SIZE(inode->i_sb) > PXT4_GOOD_OLD_INODE_SIZE)
		inode_len += ei->i_extra_isize;

	fc_inode.fc_ino = cpu_to_le32(inode->i_ino);
	tl.fc_tag = cpu_to_le16(PXT4_FC_TAG_INODE);
	tl.fc_len = cpu_to_le16(inode_len + sizeof(fc_inode.fc_ino));

	ret = -ECANCELED;
	dst = pxt4_fc_reserve_space(inode->i_sb,
		PXT4_FC_TAG_BASE_LEN + inode_len + sizeof(fc_inode.fc_ino), crc);
	if (!dst)
		goto err;

	memcpy(dst, &tl, PXT4_FC_TAG_BASE_LEN);
	dst += PXT4_FC_TAG_BASE_LEN;
	memcpy(dst, &fc_inode, sizeof(fc_inode));
	dst += sizeof(fc_inode);
	memcpy(dst, (u8 *)pxt4_raw_inode(&iloc), inode_len);
	ret = 0;
err:
	brelse(iloc.bh);
	return ret;
}

/*
 * Writes updated data ranges for the inode in question. Updates CRC.
 * Returns 0 on success, error otherwise.
 */
static int pxt4_fc_write_inode_data(struct inode *inode, u32 *crc)
{
	pxt4_lblk_t old_blk_size, cur_lblk_off, new_blk_size;
	struct pxt4_inode_info *ei = PXT4_I(inode);
	struct pxt4_map_blocks map;
	struct pxt4_fc_add_range fc_ext;
	struct pxt4_fc_del_range lrange;
	struct pxt4_extent *ex;
	int ret;

	mutex_lock(&ei->i_fc_lock);
	if (ei->i_fc_lblk_len == 0) {
		mutex_unlock(&ei->i_fc_lock);
		return 0;
	}
	old_blk_size = ei->i_fc_lblk_start;
	new_blk_size = ei->i_fc_lblk_start + ei->i_fc_lblk_len - 1;
	ei->i_fc_lblk_len = 0;
	mutex_unlock(&ei->i_fc_lock);

	cur_lblk_off = old_blk_size;
	pxt4_debug("will try writing %d to %d for inode %ld\n",
		   cur_lblk_off, new_blk_size, inode->i_ino);

	while (cur_lblk_off <= new_blk_size) {
		map.m_lblk = cur_lblk_off;
		map.m_len = new_blk_size - cur_lblk_off + 1;
		ret = pxt4_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			return -ECANCELED;

		if (map.m_len == 0) {
			cur_lblk_off++;
			continue;
		}

		if (ret == 0) {
			lrange.fc_ino = cpu_to_le32(inode->i_ino);
			lrange.fc_lblk = cpu_to_le32(map.m_lblk);
			lrange.fc_len = cpu_to_le32(map.m_len);
			if (!pxt4_fc_add_tlv(inode->i_sb, PXT4_FC_TAG_DEL_RANGE,
					    sizeof(lrange), (u8 *)&lrange, crc))
				return -ENOSPC;
		} else {
			unsigned int max = (map.m_flags & PXT4_MAP_UNWRITTEN) ?
				EXT_UNWRITTEN_MAX_LEN : EXT_INIT_MAX_LEN;

			/* Limit the number of blocks in one extent */
			map.m_len = min(max, map.m_len);

			fc_ext.fc_ino = cpu_to_le32(inode->i_ino);
			ex = (struct pxt4_extent *)&fc_ext.fc_ex;
			ex->ee_block = cpu_to_le32(map.m_lblk);
			ex->ee_len = cpu_to_le16(map.m_len);
			pxt4_ext_store_pblock(ex, map.m_pblk);
			if (map.m_flags & PXT4_MAP_UNWRITTEN)
				pxt4_ext_mark_unwritten(ex);
			else
				pxt4_ext_mark_initialized(ex);
			if (!pxt4_fc_add_tlv(inode->i_sb, PXT4_FC_TAG_ADD_RANGE,
					    sizeof(fc_ext), (u8 *)&fc_ext, crc))
				return -ENOSPC;
		}

		cur_lblk_off += map.m_len;
	}

	return 0;
}


/* Submit data for all the fast commit inodes */
static int pxt4_fc_submit_inode_data_all(journal_t *journal)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_inode_info *ei;
	int ret = 0;

	spin_lock(&sbi->s_fc_lock);
	list_for_each_entry(ei, &sbi->s_fc_q[FC_Q_MAIN], i_fc_list) {
		pxt4_set_inode_state(&ei->vfs_inode, PXT4_STATE_FC_COMMITTING);
		while (atomic_read(&ei->i_fc_updates)) {
			DEFINE_WAIT(wait);

			prepare_to_wait(&ei->i_fc_wait, &wait,
						TASK_UNINTERRUPTIBLE);
			if (atomic_read(&ei->i_fc_updates)) {
				spin_unlock(&sbi->s_fc_lock);
				schedule();
				spin_lock(&sbi->s_fc_lock);
			}
			finish_wait(&ei->i_fc_wait, &wait);
		}
		spin_unlock(&sbi->s_fc_lock);
		ret = jbd3_submit_inode_data(journal, ei->jinode);
		if (ret)
			return ret;
		spin_lock(&sbi->s_fc_lock);
	}
	spin_unlock(&sbi->s_fc_lock);

	return ret;
}

/* Wait for completion of data for all the fast commit inodes */
static int pxt4_fc_wait_inode_data_all(journal_t *journal)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_inode_info *pos, *n;
	int ret = 0;

	spin_lock(&sbi->s_fc_lock);
	list_for_each_entry_safe(pos, n, &sbi->s_fc_q[FC_Q_MAIN], i_fc_list) {
		if (!pxt4_test_inode_state(&pos->vfs_inode,
					   PXT4_STATE_FC_COMMITTING))
			continue;
		spin_unlock(&sbi->s_fc_lock);

		ret = jbd3_wait_inode_data(journal, pos->jinode);
		if (ret)
			return ret;
		spin_lock(&sbi->s_fc_lock);
	}
	spin_unlock(&sbi->s_fc_lock);

	return 0;
}

/* Commit all the directory entry updates */
static int pxt4_fc_commit_dentry_updates(journal_t *journal, u32 *crc)
__acquires(&sbi->s_fc_lock)
__releases(&sbi->s_fc_lock)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_fc_dentry_update *fc_dentry, *fc_dentry_n;
	struct inode *inode;
	struct pxt4_inode_info *ei;
	int ret;

	if (list_empty(&sbi->s_fc_dentry_q[FC_Q_MAIN]))
		return 0;
	list_for_each_entry_safe(fc_dentry, fc_dentry_n,
				 &sbi->s_fc_dentry_q[FC_Q_MAIN], fcd_list) {
		if (fc_dentry->fcd_op != PXT4_FC_TAG_CREAT) {
			spin_unlock(&sbi->s_fc_lock);
			if (!pxt4_fc_add_dentry_tlv(sb, crc, fc_dentry)) {
				ret = -ENOSPC;
				goto lock_and_exit;
			}
			spin_lock(&sbi->s_fc_lock);
			continue;
		}
		/*
		 * With fcd_dilist we need not loop in sbi->s_fc_q to get the
		 * corresponding inode pointer
		 */
		WARN_ON(list_empty(&fc_dentry->fcd_dilist));
		ei = list_first_entry(&fc_dentry->fcd_dilist,
				struct pxt4_inode_info, i_fc_dilist);
		inode = &ei->vfs_inode;
		WARN_ON(inode->i_ino != fc_dentry->fcd_ino);

		spin_unlock(&sbi->s_fc_lock);

		/*
		 * We first write the inode and then the create dirent. This
		 * allows the recovery code to create an unnamed inode first
		 * and then link it to a directory entry. This allows us
		 * to use namei.c routines almost as is and simplifies
		 * the recovery code.
		 */
		ret = pxt4_fc_write_inode(inode, crc);
		if (ret)
			goto lock_and_exit;

		ret = pxt4_fc_write_inode_data(inode, crc);
		if (ret)
			goto lock_and_exit;

		if (!pxt4_fc_add_dentry_tlv(sb, crc, fc_dentry)) {
			ret = -ENOSPC;
			goto lock_and_exit;
		}

		spin_lock(&sbi->s_fc_lock);
	}
	return 0;
lock_and_exit:
	spin_lock(&sbi->s_fc_lock);
	return ret;
}

static int pxt4_fc_perform_commit(journal_t *journal)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_inode_info *iter;
	struct pxt4_fc_head head;
	struct inode *inode;
	struct blk_plug plug;
	int ret = 0;
	u32 crc = 0;

	ret = pxt4_fc_submit_inode_data_all(journal);
	if (ret)
		return ret;

	ret = pxt4_fc_wait_inode_data_all(journal);
	if (ret)
		return ret;

	/*
	 * If file system device is different from journal device, issue a cache
	 * flush before we start writing fast commit blocks.
	 */
	if (journal->j_fs_dev != journal->j_dev)
		blkdev_issue_flush(journal->j_fs_dev);

	blk_start_plug(&plug);
	if (sbi->s_fc_bytes == 0) {
		/*
		 * Add a head tag only if this is the first fast commit
		 * in this TID.
		 */
		head.fc_features = cpu_to_le32(PXT4_FC_SUPPORTED_FEATURES);
		head.fc_tid = cpu_to_le32(
			sbi->s_journal->j_running_transaction->t_tid);
		if (!pxt4_fc_add_tlv(sb, PXT4_FC_TAG_HEAD, sizeof(head),
			(u8 *)&head, &crc)) {
			ret = -ENOSPC;
			goto out;
		}
	}

	spin_lock(&sbi->s_fc_lock);
	ret = pxt4_fc_commit_dentry_updates(journal, &crc);
	if (ret) {
		spin_unlock(&sbi->s_fc_lock);
		goto out;
	}

	list_for_each_entry(iter, &sbi->s_fc_q[FC_Q_MAIN], i_fc_list) {
		inode = &iter->vfs_inode;
		if (!pxt4_test_inode_state(inode, PXT4_STATE_FC_COMMITTING))
			continue;

		spin_unlock(&sbi->s_fc_lock);
		ret = pxt4_fc_write_inode_data(inode, &crc);
		if (ret)
			goto out;
		ret = pxt4_fc_write_inode(inode, &crc);
		if (ret)
			goto out;
		spin_lock(&sbi->s_fc_lock);
	}
	spin_unlock(&sbi->s_fc_lock);

	ret = pxt4_fc_write_tail(sb, crc);

out:
	blk_finish_plug(&plug);
	return ret;
}

static void pxt4_fc_update_stats(struct super_block *sb, int status,
				 u64 commit_time, int nblks, tid_t commit_tid)
{
	struct pxt4_fc_stats *stats = &PXT4_SB(sb)->s_fc_stats;

	pxt4_debug("Fast commit ended with status = %d for tid %u",
			status, commit_tid);
	if (status == PXT4_FC_STATUS_OK) {
		stats->fc_num_commits++;
		stats->fc_numblks += nblks;
		if (likely(stats->s_fc_avg_commit_time))
			stats->s_fc_avg_commit_time =
				(commit_time +
				 stats->s_fc_avg_commit_time * 3) / 4;
		else
			stats->s_fc_avg_commit_time = commit_time;
	} else if (status == PXT4_FC_STATUS_FAILED ||
		   status == PXT4_FC_STATUS_INELIGIBLE) {
		if (status == PXT4_FC_STATUS_FAILED)
			stats->fc_failed_commits++;
		stats->fc_ineligible_commits++;
	} else {
		stats->fc_skipped_commits++;
	}
	trace_pxt4_fc_commit_stop(sb, nblks, status, commit_tid);
}

/*
 * The main commit entry point. Performs a fast commit for transaction
 * commit_tid if needed. If it's not possible to perform a fast commit
 * due to various reasons, we fall back to full commit. Returns 0
 * on success, error otherwise.
 */
int pxt4_fc_commit(journal_t *journal, tid_t commit_tid)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	int nblks = 0, ret, bsize = journal->j_blocksize;
	int subtid = atomic_read(&sbi->s_fc_subtid);
	int status = PXT4_FC_STATUS_OK, fc_bufs_before = 0;
	ktime_t start_time, commit_time;

	if (!test_opt2(sb, JOURNAL_FAST_COMMIT))
		return jbd3_complete_transaction(journal, commit_tid);

	trace_pxt4_fc_commit_start(sb, commit_tid);

	start_time = ktime_get();

restart_fc:
	ret = jbd3_fc_begin_commit(journal, commit_tid);
	if (ret == -EALREADY) {
		/* There was an ongoing commit, check if we need to restart */
		if (atomic_read(&sbi->s_fc_subtid) <= subtid &&
			commit_tid > journal->j_commit_sequence)
			goto restart_fc;
		pxt4_fc_update_stats(sb, PXT4_FC_STATUS_SKIPPED, 0, 0,
				commit_tid);
		return 0;
	} else if (ret) {
		/*
		 * Commit couldn't start. Just update stats and perform a
		 * full commit.
		 */
		pxt4_fc_update_stats(sb, PXT4_FC_STATUS_FAILED, 0, 0,
				commit_tid);
		return jbd3_complete_transaction(journal, commit_tid);
	}

	/*
	 * After establishing journal barrier via jbd3_fc_begin_commit(), check
	 * if we are fast commit ineligible.
	 */
	if (pxt4_test_mount_flag(sb, PXT4_MF_FC_INELIGIBLE)) {
		status = PXT4_FC_STATUS_INELIGIBLE;
		goto fallback;
	}

	fc_bufs_before = (sbi->s_fc_bytes + bsize - 1) / bsize;
	ret = pxt4_fc_perform_commit(journal);
	if (ret < 0) {
		status = PXT4_FC_STATUS_FAILED;
		goto fallback;
	}
	nblks = (sbi->s_fc_bytes + bsize - 1) / bsize - fc_bufs_before;
	ret = jbd3_fc_wait_bufs(journal, nblks);
	if (ret < 0) {
		status = PXT4_FC_STATUS_FAILED;
		goto fallback;
	}
	atomic_inc(&sbi->s_fc_subtid);
	ret = jbd3_fc_end_commit(journal);
	/*
	 * weight the commit time higher than the average time so we
	 * don't react too strongly to vast changes in the commit time
	 */
	commit_time = ktime_to_ns(ktime_sub(ktime_get(), start_time));
	pxt4_fc_update_stats(sb, status, commit_time, nblks, commit_tid);
	return ret;

fallback:
	ret = jbd3_fc_end_commit_fallback(journal);
	pxt4_fc_update_stats(sb, status, 0, 0, commit_tid);
	return ret;
}

/*
 * Fast commit cleanup routine. This is called after every fast commit and
 * full commit. full is true if we are called after a full commit.
 */
static void pxt4_fc_cleanup(journal_t *journal, int full, tid_t tid)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_inode_info *iter, *iter_n;
	struct pxt4_fc_dentry_update *fc_dentry;

	if (full && sbi->s_fc_bh)
		sbi->s_fc_bh = NULL;

	trace_pxt4_fc_cleanup(journal, full, tid);
	jbd3_fc_release_bufs(journal);

	spin_lock(&sbi->s_fc_lock);
	list_for_each_entry_safe(iter, iter_n, &sbi->s_fc_q[FC_Q_MAIN],
				 i_fc_list) {
		list_del_init(&iter->i_fc_list);
		pxt4_clear_inode_state(&iter->vfs_inode,
				       PXT4_STATE_FC_COMMITTING);
		if (iter->i_sync_tid <= tid)
			pxt4_fc_reset_inode(&iter->vfs_inode);
		/* Make sure PXT4_STATE_FC_COMMITTING bit is clear */
		smp_mb();
#if (BITS_PER_LONG < 64)
		wake_up_bit(&iter->i_state_flags, PXT4_STATE_FC_COMMITTING);
#else
		wake_up_bit(&iter->i_flags, PXT4_STATE_FC_COMMITTING);
#endif
	}

	while (!list_empty(&sbi->s_fc_dentry_q[FC_Q_MAIN])) {
		fc_dentry = list_first_entry(&sbi->s_fc_dentry_q[FC_Q_MAIN],
					     struct pxt4_fc_dentry_update,
					     fcd_list);
		list_del_init(&fc_dentry->fcd_list);
		list_del_init(&fc_dentry->fcd_dilist);
		spin_unlock(&sbi->s_fc_lock);

		if (fc_dentry->fcd_name.name &&
			fc_dentry->fcd_name.len > DNAME_INLINE_LEN)
			kfree(fc_dentry->fcd_name.name);
		kmem_cache_free(pxt4_fc_dentry_cachep, fc_dentry);
		spin_lock(&sbi->s_fc_lock);
	}

	list_splice_init(&sbi->s_fc_dentry_q[FC_Q_STAGING],
				&sbi->s_fc_dentry_q[FC_Q_MAIN]);
	list_splice_init(&sbi->s_fc_q[FC_Q_STAGING],
				&sbi->s_fc_q[FC_Q_MAIN]);

	if (tid >= sbi->s_fc_ineligible_tid) {
		sbi->s_fc_ineligible_tid = 0;
		pxt4_clear_mount_flag(sb, PXT4_MF_FC_INELIGIBLE);
	}

	if (full)
		sbi->s_fc_bytes = 0;
	spin_unlock(&sbi->s_fc_lock);
	trace_pxt4_fc_stats(sb);
}

/* Ext4 Replay Path Routines */

/* Helper struct for dentry replay routines */
struct dentry_info_args {
	int parent_ino, dname_len, ino, inode_len;
	char *dname;
};

/* Same as struct pxt4_fc_tl, but uses native endianness fields */
struct pxt4_fc_tl_mem {
	u16 fc_tag;
	u16 fc_len;
};

static inline void tl_to_darg(struct dentry_info_args *darg,
			      struct pxt4_fc_tl_mem *tl, u8 *val)
{
	struct pxt4_fc_dentry_info fcd;

	memcpy(&fcd, val, sizeof(fcd));

	darg->parent_ino = le32_to_cpu(fcd.fc_parent_ino);
	darg->ino = le32_to_cpu(fcd.fc_ino);
	darg->dname = val + offsetof(struct pxt4_fc_dentry_info, fc_dname);
	darg->dname_len = tl->fc_len - sizeof(struct pxt4_fc_dentry_info);
}

static inline void pxt4_fc_get_tl(struct pxt4_fc_tl_mem *tl, u8 *val)
{
	struct pxt4_fc_tl tl_disk;

	memcpy(&tl_disk, val, PXT4_FC_TAG_BASE_LEN);
	tl->fc_len = le16_to_cpu(tl_disk.fc_len);
	tl->fc_tag = le16_to_cpu(tl_disk.fc_tag);
}

/* Unlink replay function */
static int pxt4_fc_replay_unlink(struct super_block *sb,
				 struct pxt4_fc_tl_mem *tl, u8 *val)
{
	struct inode *inode, *old_parent;
	struct qstr entry;
	struct dentry_info_args darg;
	int ret = 0;

	tl_to_darg(&darg, tl, val);

	trace_pxt4_fc_replay(sb, PXT4_FC_TAG_UNLINK, darg.ino,
			darg.parent_ino, darg.dname_len);

	entry.name = darg.dname;
	entry.len = darg.dname_len;
	inode = pxt4_iget(sb, darg.ino, PXT4_IGET_NORMAL);

	if (IS_ERR(inode)) {
		pxt4_debug("Inode %d not found", darg.ino);
		return 0;
	}

	old_parent = pxt4_iget(sb, darg.parent_ino,
				PXT4_IGET_NORMAL);
	if (IS_ERR(old_parent)) {
		pxt4_debug("Dir with inode %d not found", darg.parent_ino);
		iput(inode);
		return 0;
	}

	ret = __pxt4_unlink(old_parent, &entry, inode, NULL);
	/* -ENOENT ok coz it might not exist anymore. */
	if (ret == -ENOENT)
		ret = 0;
	iput(old_parent);
	iput(inode);
	return ret;
}

static int pxt4_fc_replay_link_internal(struct super_block *sb,
				struct dentry_info_args *darg,
				struct inode *inode)
{
	struct inode *dir = NULL;
	struct dentry *dentry_dir = NULL, *dentry_inode = NULL;
	struct qstr qstr_dname = QSTR_INIT(darg->dname, darg->dname_len);
	int ret = 0;

	dir = pxt4_iget(sb, darg->parent_ino, PXT4_IGET_NORMAL);
	if (IS_ERR(dir)) {
		pxt4_debug("Dir with inode %d not found.", darg->parent_ino);
		dir = NULL;
		goto out;
	}

	dentry_dir = d_obtain_alias(dir);
	if (IS_ERR(dentry_dir)) {
		pxt4_debug("Failed to obtain dentry");
		dentry_dir = NULL;
		goto out;
	}

	dentry_inode = d_alloc(dentry_dir, &qstr_dname);
	if (!dentry_inode) {
		pxt4_debug("Inode dentry not created.");
		ret = -ENOMEM;
		goto out;
	}

	ret = __pxt4_link(dir, inode, dentry_inode);
	/*
	 * It's possible that link already existed since data blocks
	 * for the dir in question got persisted before we crashed OR
	 * we replayed this tag and crashed before the entire replay
	 * could complete.
	 */
	if (ret && ret != -EEXIST) {
		pxt4_debug("Failed to link\n");
		goto out;
	}

	ret = 0;
out:
	if (dentry_dir) {
		d_drop(dentry_dir);
		dput(dentry_dir);
	} else if (dir) {
		iput(dir);
	}
	if (dentry_inode) {
		d_drop(dentry_inode);
		dput(dentry_inode);
	}

	return ret;
}

/* Link replay function */
static int pxt4_fc_replay_link(struct super_block *sb,
			       struct pxt4_fc_tl_mem *tl, u8 *val)
{
	struct inode *inode;
	struct dentry_info_args darg;
	int ret = 0;

	tl_to_darg(&darg, tl, val);
	trace_pxt4_fc_replay(sb, PXT4_FC_TAG_LINK, darg.ino,
			darg.parent_ino, darg.dname_len);

	inode = pxt4_iget(sb, darg.ino, PXT4_IGET_NORMAL);
	if (IS_ERR(inode)) {
		pxt4_debug("Inode not found.");
		return 0;
	}

	ret = pxt4_fc_replay_link_internal(sb, &darg, inode);
	iput(inode);
	return ret;
}

/*
 * Record all the modified inodes during replay. We use this later to setup
 * block bitmaps correctly.
 */
static int pxt4_fc_record_modified_inode(struct super_block *sb, int ino)
{
	struct pxt4_fc_replay_state *state;
	int i;

	state = &PXT4_SB(sb)->s_fc_replay_state;
	for (i = 0; i < state->fc_modified_inodes_used; i++)
		if (state->fc_modified_inodes[i] == ino)
			return 0;
	if (state->fc_modified_inodes_used == state->fc_modified_inodes_size) {
		int *fc_modified_inodes;

		fc_modified_inodes = krealloc(state->fc_modified_inodes,
				sizeof(int) * (state->fc_modified_inodes_size +
				PXT4_FC_REPLAY_REALLOC_INCREMENT),
				GFP_KERNEL);
		if (!fc_modified_inodes)
			return -ENOMEM;
		state->fc_modified_inodes = fc_modified_inodes;
		state->fc_modified_inodes_size +=
			PXT4_FC_REPLAY_REALLOC_INCREMENT;
	}
	state->fc_modified_inodes[state->fc_modified_inodes_used++] = ino;
	return 0;
}

/*
 * Inode replay function
 */
static int pxt4_fc_replay_inode(struct super_block *sb,
				struct pxt4_fc_tl_mem *tl, u8 *val)
{
	struct pxt4_fc_inode fc_inode;
	struct pxt4_inode *raw_inode;
	struct pxt4_inode *raw_fc_inode;
	struct inode *inode = NULL;
	struct pxt4_iloc iloc;
	int inode_len, ino, ret, tag = tl->fc_tag;
	struct pxt4_extent_header *eh;
	size_t off_gen = offsetof(struct pxt4_inode, i_generation);

	memcpy(&fc_inode, val, sizeof(fc_inode));

	ino = le32_to_cpu(fc_inode.fc_ino);
	trace_pxt4_fc_replay(sb, tag, ino, 0, 0);

	inode = pxt4_iget(sb, ino, PXT4_IGET_NORMAL);
	if (!IS_ERR(inode)) {
		pxt4_ext_clear_bb(inode);
		iput(inode);
	}
	inode = NULL;

	ret = pxt4_fc_record_modified_inode(sb, ino);
	if (ret)
		goto out;

	raw_fc_inode = (struct pxt4_inode *)
		(val + offsetof(struct pxt4_fc_inode, fc_raw_inode));
	ret = pxt4_get_fc_inode_loc(sb, ino, &iloc);
	if (ret)
		goto out;

	inode_len = tl->fc_len - sizeof(struct pxt4_fc_inode);
	raw_inode = pxt4_raw_inode(&iloc);

	memcpy(raw_inode, raw_fc_inode, offsetof(struct pxt4_inode, i_block));
	memcpy((u8 *)raw_inode + off_gen, (u8 *)raw_fc_inode + off_gen,
	       inode_len - off_gen);
	if (le32_to_cpu(raw_inode->i_flags) & PXT4_EXTENTS_FL) {
		eh = (struct pxt4_extent_header *)(&raw_inode->i_block[0]);
		if (eh->eh_magic != PXT4_EXT_MAGIC) {
			memset(eh, 0, sizeof(*eh));
			eh->eh_magic = PXT4_EXT_MAGIC;
			eh->eh_max = cpu_to_le16(
				(sizeof(raw_inode->i_block) -
				 sizeof(struct pxt4_extent_header))
				 / sizeof(struct pxt4_extent));
		}
	} else if (le32_to_cpu(raw_inode->i_flags) & PXT4_INLINE_DATA_FL) {
		memcpy(raw_inode->i_block, raw_fc_inode->i_block,
			sizeof(raw_inode->i_block));
	}

	/* Immediately update the inode on disk. */
	ret = pxt4_handle_dirty_metadata(NULL, NULL, iloc.bh);
	if (ret)
		goto out;
	ret = sync_dirty_buffer(iloc.bh);
	if (ret)
		goto out;
	ret = pxt4_mark_inode_used(sb, ino);
	if (ret)
		goto out;

	/* Given that we just wrote the inode on disk, this SHOULD succeed. */
	inode = pxt4_iget(sb, ino, PXT4_IGET_NORMAL);
	if (IS_ERR(inode)) {
		pxt4_debug("Inode not found.");
		return -EFSCORRUPTED;
	}

	/*
	 * Our allocator could have made different decisions than before
	 * crashing. This should be fixed but until then, we calculate
	 * the number of blocks the inode.
	 */
	if (!pxt4_test_inode_flag(inode, PXT4_INODE_INLINE_DATA))
		pxt4_ext_replay_set_iblocks(inode);

	inode->i_generation = le32_to_cpu(pxt4_raw_inode(&iloc)->i_generation);
	pxt4_reset_inode_seed(inode);

	pxt4_inode_csum_set(inode, pxt4_raw_inode(&iloc), PXT4_I(inode));
	ret = pxt4_handle_dirty_metadata(NULL, NULL, iloc.bh);
	sync_dirty_buffer(iloc.bh);
	brelse(iloc.bh);
out:
	iput(inode);
	if (!ret)
		blkdev_issue_flush(sb->s_bdev);

	return 0;
}

/*
 * Dentry create replay function.
 *
 * PXT4_FC_TAG_CREAT is preceded by PXT4_FC_TAG_INODE_FULL. Which means, the
 * inode for which we are trying to create a dentry here, should already have
 * been replayed before we start here.
 */
static int pxt4_fc_replay_create(struct super_block *sb,
				 struct pxt4_fc_tl_mem *tl, u8 *val)
{
	int ret = 0;
	struct inode *inode = NULL;
	struct inode *dir = NULL;
	struct dentry_info_args darg;

	tl_to_darg(&darg, tl, val);

	trace_pxt4_fc_replay(sb, PXT4_FC_TAG_CREAT, darg.ino,
			darg.parent_ino, darg.dname_len);

	/* This takes care of update group descriptor and other metadata */
	ret = pxt4_mark_inode_used(sb, darg.ino);
	if (ret)
		goto out;

	inode = pxt4_iget(sb, darg.ino, PXT4_IGET_NORMAL);
	if (IS_ERR(inode)) {
		pxt4_debug("inode %d not found.", darg.ino);
		inode = NULL;
		ret = -EINVAL;
		goto out;
	}

	if (S_ISDIR(inode->i_mode)) {
		/*
		 * If we are creating a directory, we need to make sure that the
		 * dot and dot dot dirents are setup properly.
		 */
		dir = pxt4_iget(sb, darg.parent_ino, PXT4_IGET_NORMAL);
		if (IS_ERR(dir)) {
			pxt4_debug("Dir %d not found.", darg.ino);
			goto out;
		}
		ret = pxt4_init_new_dir(NULL, dir, inode);
		iput(dir);
		if (ret) {
			ret = 0;
			goto out;
		}
	}
	ret = pxt4_fc_replay_link_internal(sb, &darg, inode);
	if (ret)
		goto out;
	set_nlink(inode, 1);
	pxt4_mark_inode_dirty(NULL, inode);
out:
	iput(inode);
	return ret;
}

/*
 * Record physical disk regions which are in use as per fast commit area,
 * and used by inodes during replay phase. Our simple replay phase
 * allocator excludes these regions from allocation.
 */
int pxt4_fc_record_regions(struct super_block *sb, int ino,
		pxt4_lblk_t lblk, pxt4_fsblk_t pblk, int len, int replay)
{
	struct pxt4_fc_replay_state *state;
	struct pxt4_fc_alloc_region *region;

	state = &PXT4_SB(sb)->s_fc_replay_state;
	/*
	 * during replay phase, the fc_regions_valid may not same as
	 * fc_regions_used, update it when do new additions.
	 */
	if (replay && state->fc_regions_used != state->fc_regions_valid)
		state->fc_regions_used = state->fc_regions_valid;
	if (state->fc_regions_used == state->fc_regions_size) {
		struct pxt4_fc_alloc_region *fc_regions;

		fc_regions = krealloc(state->fc_regions,
				      sizeof(struct pxt4_fc_alloc_region) *
				      (state->fc_regions_size +
				       PXT4_FC_REPLAY_REALLOC_INCREMENT),
				      GFP_KERNEL);
		if (!fc_regions)
			return -ENOMEM;
		state->fc_regions_size +=
			PXT4_FC_REPLAY_REALLOC_INCREMENT;
		state->fc_regions = fc_regions;
	}
	region = &state->fc_regions[state->fc_regions_used++];
	region->ino = ino;
	region->lblk = lblk;
	region->pblk = pblk;
	region->len = len;

	if (replay)
		state->fc_regions_valid++;

	return 0;
}

/* Replay add range tag */
static int pxt4_fc_replay_add_range(struct super_block *sb,
				    struct pxt4_fc_tl_mem *tl, u8 *val)
{
	struct pxt4_fc_add_range fc_add_ex;
	struct pxt4_extent newex, *ex;
	struct inode *inode;
	pxt4_lblk_t start, cur;
	int remaining, len;
	pxt4_fsblk_t start_pblk;
	struct pxt4_map_blocks map;
	struct pxt4_ext_path *path = NULL;
	int ret;

	memcpy(&fc_add_ex, val, sizeof(fc_add_ex));
	ex = (struct pxt4_extent *)&fc_add_ex.fc_ex;

	trace_pxt4_fc_replay(sb, PXT4_FC_TAG_ADD_RANGE,
		le32_to_cpu(fc_add_ex.fc_ino), le32_to_cpu(ex->ee_block),
		pxt4_ext_get_actual_len(ex));

	inode = pxt4_iget(sb, le32_to_cpu(fc_add_ex.fc_ino), PXT4_IGET_NORMAL);
	if (IS_ERR(inode)) {
		pxt4_debug("Inode not found.");
		return 0;
	}

	ret = pxt4_fc_record_modified_inode(sb, inode->i_ino);
	if (ret)
		goto out;

	start = le32_to_cpu(ex->ee_block);
	start_pblk = pxt4_ext_pblock(ex);
	len = pxt4_ext_get_actual_len(ex);

	cur = start;
	remaining = len;
	pxt4_debug("ADD_RANGE, lblk %d, pblk %lld, len %d, unwritten %d, inode %ld\n",
		  start, start_pblk, len, pxt4_ext_is_unwritten(ex),
		  inode->i_ino);

	while (remaining > 0) {
		map.m_lblk = cur;
		map.m_len = remaining;
		map.m_pblk = 0;
		ret = pxt4_map_blocks(NULL, inode, &map, 0);

		if (ret < 0)
			goto out;

		if (ret == 0) {
			/* Range is not mapped */
			path = pxt4_find_extent(inode, cur, NULL, 0);
			if (IS_ERR(path))
				goto out;
			memset(&newex, 0, sizeof(newex));
			newex.ee_block = cpu_to_le32(cur);
			pxt4_ext_store_pblock(
				&newex, start_pblk + cur - start);
			newex.ee_len = cpu_to_le16(map.m_len);
			if (pxt4_ext_is_unwritten(ex))
				pxt4_ext_mark_unwritten(&newex);
			down_write(&PXT4_I(inode)->i_data_sem);
			ret = pxt4_ext_insert_extent(
				NULL, inode, &path, &newex, 0);
			up_write((&PXT4_I(inode)->i_data_sem));
			pxt4_free_ext_path(path);
			if (ret)
				goto out;
			goto next;
		}

		if (start_pblk + cur - start != map.m_pblk) {
			/*
			 * Logical to physical mapping changed. This can happen
			 * if this range was removed and then reallocated to
			 * map to new physical blocks during a fast commit.
			 */
			ret = pxt4_ext_replay_update_ex(inode, cur, map.m_len,
					pxt4_ext_is_unwritten(ex),
					start_pblk + cur - start);
			if (ret)
				goto out;
			/*
			 * Mark the old blocks as free since they aren't used
			 * anymore. We maintain an array of all the modified
			 * inodes. In case these blocks are still used at either
			 * a different logical range in the same inode or in
			 * some different inode, we will mark them as allocated
			 * at the end of the FC replay using our array of
			 * modified inodes.
			 */
			pxt4_mb_mark_bb(inode->i_sb, map.m_pblk, map.m_len, 0);
			goto next;
		}

		/* Range is mapped and needs a state change */
		pxt4_debug("Converting from %ld to %d %lld",
				map.m_flags & PXT4_MAP_UNWRITTEN,
			pxt4_ext_is_unwritten(ex), map.m_pblk);
		ret = pxt4_ext_replay_update_ex(inode, cur, map.m_len,
					pxt4_ext_is_unwritten(ex), map.m_pblk);
		if (ret)
			goto out;
		/*
		 * We may have split the extent tree while toggling the state.
		 * Try to shrink the extent tree now.
		 */
		pxt4_ext_replay_shrink_inode(inode, start + len);
next:
		cur += map.m_len;
		remaining -= map.m_len;
	}
	pxt4_ext_replay_shrink_inode(inode, i_size_read(inode) >>
					sb->s_blocksize_bits);
out:
	iput(inode);
	return 0;
}

/* Replay DEL_RANGE tag */
static int
pxt4_fc_replay_del_range(struct super_block *sb,
			 struct pxt4_fc_tl_mem *tl, u8 *val)
{
	struct inode *inode;
	struct pxt4_fc_del_range lrange;
	struct pxt4_map_blocks map;
	pxt4_lblk_t cur, remaining;
	int ret;

	memcpy(&lrange, val, sizeof(lrange));
	cur = le32_to_cpu(lrange.fc_lblk);
	remaining = le32_to_cpu(lrange.fc_len);

	trace_pxt4_fc_replay(sb, PXT4_FC_TAG_DEL_RANGE,
		le32_to_cpu(lrange.fc_ino), cur, remaining);

	inode = pxt4_iget(sb, le32_to_cpu(lrange.fc_ino), PXT4_IGET_NORMAL);
	if (IS_ERR(inode)) {
		pxt4_debug("Inode %d not found", le32_to_cpu(lrange.fc_ino));
		return 0;
	}

	ret = pxt4_fc_record_modified_inode(sb, inode->i_ino);
	if (ret)
		goto out;

	pxt4_debug("DEL_RANGE, inode %ld, lblk %d, len %d\n",
			inode->i_ino, le32_to_cpu(lrange.fc_lblk),
			le32_to_cpu(lrange.fc_len));
	while (remaining > 0) {
		map.m_lblk = cur;
		map.m_len = remaining;

		ret = pxt4_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			remaining -= ret;
			cur += ret;
			pxt4_mb_mark_bb(inode->i_sb, map.m_pblk, map.m_len, 0);
		} else {
			remaining -= map.m_len;
			cur += map.m_len;
		}
	}

	down_write(&PXT4_I(inode)->i_data_sem);
	ret = pxt4_ext_remove_space(inode, le32_to_cpu(lrange.fc_lblk),
				le32_to_cpu(lrange.fc_lblk) +
				le32_to_cpu(lrange.fc_len) - 1);
	up_write(&PXT4_I(inode)->i_data_sem);
	if (ret)
		goto out;
	pxt4_ext_replay_shrink_inode(inode,
		i_size_read(inode) >> sb->s_blocksize_bits);
	pxt4_mark_inode_dirty(NULL, inode);
out:
	iput(inode);
	return 0;
}

static void pxt4_fc_set_bitmaps_and_counters(struct super_block *sb)
{
	struct pxt4_fc_replay_state *state;
	struct inode *inode;
	struct pxt4_ext_path *path = NULL;
	struct pxt4_map_blocks map;
	int i, ret, j;
	pxt4_lblk_t cur, end;

	state = &PXT4_SB(sb)->s_fc_replay_state;
	for (i = 0; i < state->fc_modified_inodes_used; i++) {
		inode = pxt4_iget(sb, state->fc_modified_inodes[i],
			PXT4_IGET_NORMAL);
		if (IS_ERR(inode)) {
			pxt4_debug("Inode %d not found.",
				state->fc_modified_inodes[i]);
			continue;
		}
		cur = 0;
		end = EXT_MAX_BLOCKS;
		if (pxt4_test_inode_flag(inode, PXT4_INODE_INLINE_DATA)) {
			iput(inode);
			continue;
		}
		while (cur < end) {
			map.m_lblk = cur;
			map.m_len = end - cur;

			ret = pxt4_map_blocks(NULL, inode, &map, 0);
			if (ret < 0)
				break;

			if (ret > 0) {
				path = pxt4_find_extent(inode, map.m_lblk, NULL, 0);
				if (!IS_ERR(path)) {
					for (j = 0; j < path->p_depth; j++)
						pxt4_mb_mark_bb(inode->i_sb,
							path[j].p_block, 1, 1);
					pxt4_free_ext_path(path);
				}
				cur += ret;
				pxt4_mb_mark_bb(inode->i_sb, map.m_pblk,
							map.m_len, 1);
			} else {
				cur = cur + (map.m_len ? map.m_len : 1);
			}
		}
		iput(inode);
	}
}

/*
 * Check if block is in excluded regions for block allocation. The simple
 * allocator that runs during replay phase is calls this function to see
 * if it is okay to use a block.
 */
bool pxt4_fc_replay_check_excluded(struct super_block *sb, pxt4_fsblk_t blk)
{
	int i;
	struct pxt4_fc_replay_state *state;

	state = &PXT4_SB(sb)->s_fc_replay_state;
	for (i = 0; i < state->fc_regions_valid; i++) {
		if (state->fc_regions[i].ino == 0 ||
			state->fc_regions[i].len == 0)
			continue;
		if (in_range(blk, state->fc_regions[i].pblk,
					state->fc_regions[i].len))
			return true;
	}
	return false;
}

/* Cleanup function called after replay */
void pxt4_fc_replay_cleanup(struct super_block *sb)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	sbi->s_mount_state &= ~PXT4_FC_REPLAY;
	kfree(sbi->s_fc_replay_state.fc_regions);
	kfree(sbi->s_fc_replay_state.fc_modified_inodes);
}

static bool pxt4_fc_value_len_isvalid(struct pxt4_sb_info *sbi,
				      int tag, int len)
{
	switch (tag) {
	case PXT4_FC_TAG_ADD_RANGE:
		return len == sizeof(struct pxt4_fc_add_range);
	case PXT4_FC_TAG_DEL_RANGE:
		return len == sizeof(struct pxt4_fc_del_range);
	case PXT4_FC_TAG_CREAT:
	case PXT4_FC_TAG_LINK:
	case PXT4_FC_TAG_UNLINK:
		len -= sizeof(struct pxt4_fc_dentry_info);
		return len >= 1 && len <= PXT4_NAME_LEN;
	case PXT4_FC_TAG_INODE:
		len -= sizeof(struct pxt4_fc_inode);
		return len >= PXT4_GOOD_OLD_INODE_SIZE &&
			len <= sbi->s_inode_size;
	case PXT4_FC_TAG_PAD:
		return true; /* padding can have any length */
	case PXT4_FC_TAG_TAIL:
		return len >= sizeof(struct pxt4_fc_tail);
	case PXT4_FC_TAG_HEAD:
		return len == sizeof(struct pxt4_fc_head);
	}
	return false;
}

/*
 * Recovery Scan phase handler
 *
 * This function is called during the scan phase and is responsible
 * for doing following things:
 * - Make sure the fast commit area has valid tags for replay
 * - Count number of tags that need to be replayed by the replay handler
 * - Verify CRC
 * - Create a list of excluded blocks for allocation during replay phase
 *
 * This function returns JBD3_FC_REPLAY_CONTINUE to indicate that SCAN is
 * incomplete and JBD3 should send more blocks. It returns JBD3_FC_REPLAY_STOP
 * to indicate that scan has finished and JBD3 can now start replay phase.
 * It returns a negative error to indicate that there was an error. At the end
 * of a successful scan phase, sbi->s_fc_replay_state.fc_replay_num_tags is set
 * to indicate the number of tags that need to replayed during the replay phase.
 */
static int pxt4_fc_replay_scan(journal_t *journal,
				struct buffer_head *bh, int off,
				tid_t expected_tid)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_fc_replay_state *state;
	int ret = JBD3_FC_REPLAY_CONTINUE;
	struct pxt4_fc_add_range ext;
	struct pxt4_fc_tl_mem tl;
	struct pxt4_fc_tail tail;
	__u8 *start, *end, *cur, *val;
	struct pxt4_fc_head head;
	struct pxt4_extent *ex;

	state = &sbi->s_fc_replay_state;

	start = (u8 *)bh->b_data;
	end = start + journal->j_blocksize;

	if (state->fc_replay_expected_off == 0) {
		state->fc_cur_tag = 0;
		state->fc_replay_num_tags = 0;
		state->fc_crc = 0;
		state->fc_regions = NULL;
		state->fc_regions_valid = state->fc_regions_used =
			state->fc_regions_size = 0;
		/* Check if we can stop early */
		if (le16_to_cpu(((struct pxt4_fc_tl *)start)->fc_tag)
			!= PXT4_FC_TAG_HEAD)
			return 0;
	}

	if (off != state->fc_replay_expected_off) {
		ret = -EFSCORRUPTED;
		goto out_err;
	}

	state->fc_replay_expected_off++;
	for (cur = start; cur <= end - PXT4_FC_TAG_BASE_LEN;
	     cur = cur + PXT4_FC_TAG_BASE_LEN + tl.fc_len) {
		pxt4_fc_get_tl(&tl, cur);
		val = cur + PXT4_FC_TAG_BASE_LEN;
		if (tl.fc_len > end - val ||
		    !pxt4_fc_value_len_isvalid(sbi, tl.fc_tag, tl.fc_len)) {
			ret = state->fc_replay_num_tags ?
				JBD3_FC_REPLAY_STOP : -ECANCELED;
			goto out_err;
		}
		pxt4_debug("Scan phase, tag:%s, blk %lld\n",
			   tag2str(tl.fc_tag), bh->b_blocknr);
		switch (tl.fc_tag) {
		case PXT4_FC_TAG_ADD_RANGE:
			memcpy(&ext, val, sizeof(ext));
			ex = (struct pxt4_extent *)&ext.fc_ex;
			ret = pxt4_fc_record_regions(sb,
				le32_to_cpu(ext.fc_ino),
				le32_to_cpu(ex->ee_block), pxt4_ext_pblock(ex),
				pxt4_ext_get_actual_len(ex), 0);
			if (ret < 0)
				break;
			ret = JBD3_FC_REPLAY_CONTINUE;
			fallthrough;
		case PXT4_FC_TAG_DEL_RANGE:
		case PXT4_FC_TAG_LINK:
		case PXT4_FC_TAG_UNLINK:
		case PXT4_FC_TAG_CREAT:
		case PXT4_FC_TAG_INODE:
		case PXT4_FC_TAG_PAD:
			state->fc_cur_tag++;
			state->fc_crc = pxt4_chksum(sbi, state->fc_crc, cur,
				PXT4_FC_TAG_BASE_LEN + tl.fc_len);
			break;
		case PXT4_FC_TAG_TAIL:
			state->fc_cur_tag++;
			memcpy(&tail, val, sizeof(tail));
			state->fc_crc = pxt4_chksum(sbi, state->fc_crc, cur,
						PXT4_FC_TAG_BASE_LEN +
						offsetof(struct pxt4_fc_tail,
						fc_crc));
			if (le32_to_cpu(tail.fc_tid) == expected_tid &&
				le32_to_cpu(tail.fc_crc) == state->fc_crc) {
				state->fc_replay_num_tags = state->fc_cur_tag;
				state->fc_regions_valid =
					state->fc_regions_used;
			} else {
				ret = state->fc_replay_num_tags ?
					JBD3_FC_REPLAY_STOP : -EFSBADCRC;
			}
			state->fc_crc = 0;
			break;
		case PXT4_FC_TAG_HEAD:
			memcpy(&head, val, sizeof(head));
			if (le32_to_cpu(head.fc_features) &
				~PXT4_FC_SUPPORTED_FEATURES) {
				ret = -EOPNOTSUPP;
				break;
			}
			if (le32_to_cpu(head.fc_tid) != expected_tid) {
				ret = JBD3_FC_REPLAY_STOP;
				break;
			}
			state->fc_cur_tag++;
			state->fc_crc = pxt4_chksum(sbi, state->fc_crc, cur,
				PXT4_FC_TAG_BASE_LEN + tl.fc_len);
			break;
		default:
			ret = state->fc_replay_num_tags ?
				JBD3_FC_REPLAY_STOP : -ECANCELED;
		}
		if (ret < 0 || ret == JBD3_FC_REPLAY_STOP)
			break;
	}

out_err:
	trace_pxt4_fc_replay_scan(sb, ret, off);
	return ret;
}

/*
 * Main recovery path entry point.
 * The meaning of return codes is similar as above.
 */
static int pxt4_fc_replay(journal_t *journal, struct buffer_head *bh,
				enum passtype pass, int off, tid_t expected_tid)
{
	struct super_block *sb = journal->j_private;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	struct pxt4_fc_tl_mem tl;
	__u8 *start, *end, *cur, *val;
	int ret = JBD3_FC_REPLAY_CONTINUE;
	struct pxt4_fc_replay_state *state = &sbi->s_fc_replay_state;
	struct pxt4_fc_tail tail;

	if (pass == PASS_SCAN) {
		state->fc_current_pass = PASS_SCAN;
		return pxt4_fc_replay_scan(journal, bh, off, expected_tid);
	}

	if (state->fc_current_pass != pass) {
		state->fc_current_pass = pass;
		sbi->s_mount_state |= PXT4_FC_REPLAY;
	}
	if (!sbi->s_fc_replay_state.fc_replay_num_tags) {
		pxt4_debug("Replay stops\n");
		pxt4_fc_set_bitmaps_and_counters(sb);
		return 0;
	}

#ifdef CONFIG_PXT4_DEBUG
	if (sbi->s_fc_debug_max_replay && off >= sbi->s_fc_debug_max_replay) {
		pr_warn("Dropping fc block %d because max_replay set\n", off);
		return JBD3_FC_REPLAY_STOP;
	}
#endif

	start = (u8 *)bh->b_data;
	end = start + journal->j_blocksize;

	for (cur = start; cur <= end - PXT4_FC_TAG_BASE_LEN;
	     cur = cur + PXT4_FC_TAG_BASE_LEN + tl.fc_len) {
		pxt4_fc_get_tl(&tl, cur);
		val = cur + PXT4_FC_TAG_BASE_LEN;

		if (state->fc_replay_num_tags == 0) {
			ret = JBD3_FC_REPLAY_STOP;
			pxt4_fc_set_bitmaps_and_counters(sb);
			break;
		}

		pxt4_debug("Replay phase, tag:%s\n", tag2str(tl.fc_tag));
		state->fc_replay_num_tags--;
		switch (tl.fc_tag) {
		case PXT4_FC_TAG_LINK:
			ret = pxt4_fc_replay_link(sb, &tl, val);
			break;
		case PXT4_FC_TAG_UNLINK:
			ret = pxt4_fc_replay_unlink(sb, &tl, val);
			break;
		case PXT4_FC_TAG_ADD_RANGE:
			ret = pxt4_fc_replay_add_range(sb, &tl, val);
			break;
		case PXT4_FC_TAG_CREAT:
			ret = pxt4_fc_replay_create(sb, &tl, val);
			break;
		case PXT4_FC_TAG_DEL_RANGE:
			ret = pxt4_fc_replay_del_range(sb, &tl, val);
			break;
		case PXT4_FC_TAG_INODE:
			ret = pxt4_fc_replay_inode(sb, &tl, val);
			break;
		case PXT4_FC_TAG_PAD:
			trace_pxt4_fc_replay(sb, PXT4_FC_TAG_PAD, 0,
					     tl.fc_len, 0);
			break;
		case PXT4_FC_TAG_TAIL:
			trace_pxt4_fc_replay(sb, PXT4_FC_TAG_TAIL,
					     0, tl.fc_len, 0);
			memcpy(&tail, val, sizeof(tail));
			WARN_ON(le32_to_cpu(tail.fc_tid) != expected_tid);
			break;
		case PXT4_FC_TAG_HEAD:
			break;
		default:
			trace_pxt4_fc_replay(sb, tl.fc_tag, 0, tl.fc_len, 0);
			ret = -ECANCELED;
			break;
		}
		if (ret < 0)
			break;
		ret = JBD3_FC_REPLAY_CONTINUE;
	}
	return ret;
}

void pxt4_fc_init(struct super_block *sb, journal_t *journal)
{
	/*
	 * We set replay callback even if fast commit disabled because we may
	 * could still have fast commit blocks that need to be replayed even if
	 * fast commit has now been turned off.
	 */
	journal->j_fc_replay_callback = pxt4_fc_replay;
	if (!test_opt2(sb, JOURNAL_FAST_COMMIT))
		return;
	journal->j_fc_cleanup_callback = pxt4_fc_cleanup;
}

static const char * const fc_ineligible_reasons[] = {
	[PXT4_FC_REASON_XATTR] = "Extended attributes changed",
	[PXT4_FC_REASON_CROSS_RENAME] = "Cross rename",
	[PXT4_FC_REASON_JOURNAL_FLAG_CHANGE] = "Journal flag changed",
	[PXT4_FC_REASON_NOMEM] = "Insufficient memory",
	[PXT4_FC_REASON_SWAP_BOOT] = "Swap boot",
	[PXT4_FC_REASON_RESIZE] = "Resize",
	[PXT4_FC_REASON_RENAME_DIR] = "Dir renamed",
	[PXT4_FC_REASON_FALLOC_RANGE] = "Falloc range op",
	[PXT4_FC_REASON_INODE_JOURNAL_DATA] = "Data journalling",
	[PXT4_FC_REASON_ENCRYPTED_FILENAME] = "Encrypted filename",
};

int pxt4_fc_info_show(struct seq_file *seq, void *v)
{
	struct pxt4_sb_info *sbi = PXT4_SB((struct super_block *)seq->private);
	struct pxt4_fc_stats *stats = &sbi->s_fc_stats;
	int i;

	if (v != SEQ_START_TOKEN)
		return 0;

	seq_printf(seq,
		"fc stats:\n%ld commits\n%ld ineligible\n%ld numblks\n%lluus avg_commit_time\n",
		   stats->fc_num_commits, stats->fc_ineligible_commits,
		   stats->fc_numblks,
		   div_u64(stats->s_fc_avg_commit_time, 1000));
	seq_puts(seq, "Ineligible reasons:\n");
	for (i = 0; i < PXT4_FC_REASON_MAX; i++)
		seq_printf(seq, "\"%s\":\t%d\n", fc_ineligible_reasons[i],
			stats->fc_ineligible_reason_count[i]);

	return 0;
}

int __init pxt4_fc_init_dentry_cache(void)
{
	pxt4_fc_dentry_cachep = KMEM_CACHE(pxt4_fc_dentry_update,
					   SLAB_RECLAIM_ACCOUNT);

	if (pxt4_fc_dentry_cachep == NULL)
		return -ENOMEM;

	return 0;
}

void pxt4_fc_destroy_dentry_cache(void)
{
	kmem_cache_destroy(pxt4_fc_dentry_cachep);
}
