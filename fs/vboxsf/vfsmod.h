/*
 * VirtualBox Guest Shared Folders support: module header.
 *
 * Copyright (C) 2006-2016 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 */

#ifndef VFSMOD_H
#define VFSMOD_H

#include <linux/backing-dev.h>
#include <linux/version.h>
#include "vboxsf_wrappers.h"

#define DIR_BUFFER_SIZE SZ_16K

/* per-shared folder information */
struct sf_glob_info {
	SHFLROOT root;
	struct nls_table *nls;
	int ttl;
	int uid;
	int gid;
	int dmode;
	int fmode;
	int dmask;
	int fmask;
};

/* per-inode information */
struct sf_inode_info {
	/* which file */
	SHFLSTRING *path;
	/* some information was changed, update data on next revalidate */
	int force_restat;
	/* directory content changed, update the whole directory on next sf_getdent */
	int force_reread;
	/* file structure, only valid between open() and release() */
	struct file *file;
	/* handle valid if a file was created with sf_create_aux until it will
	 * be opened with sf_reg_open() */
	SHFLHANDLE handle;
};

struct sf_dir_info {
	struct list_head info_list;
};

struct sf_dir_buf {
	size_t cEntries;
	size_t cbFree;
	size_t cbUsed;
	void *buf;
	struct list_head head;
};

struct sf_reg_info {
	SHFLHANDLE handle;
};

/* globals */
extern struct inode_operations sf_dir_iops;
extern struct inode_operations sf_lnk_iops;
extern struct inode_operations sf_reg_iops;
extern struct file_operations sf_dir_fops;
extern struct file_operations sf_reg_fops;
extern struct dentry_operations sf_dentry_ops;
extern struct address_space_operations sf_reg_aops;

void sf_init_inode(struct sf_glob_info *sf_g, struct inode *inode,
		   const struct shfl_fsobjinfo *info);
int sf_stat(const char *caller, struct sf_glob_info *sf_g,
	    SHFLSTRING * path, struct shfl_fsobjinfo *result, int ok_to_fail);
int sf_inode_revalidate(struct dentry *dentry);
int sf_getattr(const struct path *path, struct kstat *kstat,
	       u32 request_mask, unsigned int query_flags);
int sf_setattr(struct dentry *dentry, struct iattr *iattr);
int sf_path_from_dentry(const char *caller, struct sf_glob_info *sf_g,
		        struct sf_inode_info *sf_i,
		        struct dentry *dentry, SHFLSTRING ** result);
int sf_nlscpy(struct sf_glob_info *sf_g, char *name,
	      size_t name_bound_len, const unsigned char *utf8_name,
	      size_t utf8_len);
void sf_dir_info_free(struct sf_dir_info *p);
void sf_dir_info_empty(struct sf_dir_info *p);
struct sf_dir_info *sf_dir_info_alloc(void);
int sf_dir_read_all(struct sf_glob_info *sf_g,
		    struct sf_inode_info *sf_i, struct sf_dir_info *sf_d,
		    SHFLHANDLE handle);
int sf_get_volume_info(struct super_block *sb, struct kstatfs *stat);

/*
 * Following casts are here to prevent assignment of void * to
 * pointers of arbitrary type.
 */
#define GET_GLOB_INFO(sb)       ((struct sf_glob_info *) (sb)->s_fs_info)
#define SET_GLOB_INFO(sb, sf_g) (sb)->s_fs_info = sf_g

#define GET_INODE_INFO(i)       ((struct sf_inode_info *) (i)->i_private)
#define SET_INODE_INFO(i, sf_i) (i)->i_private = sf_i

#define GET_F_DENTRY(f)         (f->f_path.dentry)

#endif
