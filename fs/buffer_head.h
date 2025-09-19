#include <linux/types.h>
#include <linux/blk_types.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/pagemap.h>
#include <linux/wait.h>
#include <linux/atomic.h>

struct buffer_head *__my_getblk_gfp(struct block_device *bdev, sector_t block, unsigned size, gfp_t gfp);

static inline struct buffer_head *
my_sb_getblk(struct super_block *sb, sector_t block)
{
    return __my_getblk_gfp(sb->s_bdev, block, sb->s_blocksize, __GFP_MOVABLE);
}

void my_mark_buffer_dirty(struct buffer_head *bh);

void __my_folio_mark_dirty(struct folio *folio, struct address_space *mapping, int warn);
