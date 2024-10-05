/* SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: Copyright (c) 2024 Ian Hangartner <icrashstuff at outlook dot com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#ifdef ENABLE_STATX
#define HAVE_STATX
#endif

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "file.h"
#include "util.h"

/**
 * A simple wrapper over fuse_get_context()->private_data to limit line length
 */
static struct filesystem_t* get_filesytem_from_fuse_context()
{
    struct fuse_context* ctx = fuse_get_context();
    if (ctx == NULL)
        return NULL;
    return ctx->private_data;
}

static int ramfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi, enum fuse_readdir_flags flags)
{
    printf("[%s:%d]: Path: \"%s\"\n", __func__, __LINE__, path);

    struct lookup_t* cur_lookup   = NULL;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (cur_lookup == NULL && !find_lookup(__func__, path, _root_lookup, &cur_lookup))
        return -ENOENT;

    if (!(cur_lookup->inode_ptr->mode & S_IFDIR))
        return -ENOTDIR;

    filler(buf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    filler(buf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);

    if (cur_lookup->child == NULL)
        return 0;
    cur_lookup = cur_lookup->child;

    while (cur_lookup != NULL)
    {
        if (cur_lookup->basename != NULL)
            filler(buf, cur_lookup->basename, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
        cur_lookup = cur_lookup->next;
    }
    return 0;
}

static int ramfs_truncate(const char* path, off_t size, struct fuse_file_info* fi);
static int ramfs_open(const char* path, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);

    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (find_inode(__func__, path, _root_lookup, (struct inode_t**)&fi->fh))
    {
        if (((struct inode_t*)fi->fh)->mode & S_IFDIR)
            return -EISDIR;
        ((struct inode_t*)fi->fh)->nrefs++;
    }
    else
    {
        fi->fh = 0;
        return -ENOENT;
    }
    if ((fi->flags) & O_TRUNC)
        ramfs_truncate(path, 0, fi);

    return 0;
}

static int ramfs_read(const char* path, char* buf, size_t size, off_t _offset, struct fuse_file_info* fi)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);

    struct inode_t*  inode        = fi == NULL ? NULL : ((struct inode_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (inode == NULL && !find_inode(__func__, path, _root_lookup, &inode))
        return -ENOENT;
    if (inode->mode & S_IFDIR)
        return -EISDIR;

    inode_update_times(inode, INODE_TIME_LEVEL_ACCESS);

    size_t offset = _offset;
    if (offset < inode->file_size && inode->buf != NULL)
    {
        if (offset + size > inode->file_size)
            size = inode->file_size - offset;
        memcpy(buf, &inode->buf[offset], size);
        return size;
    }
    else
        return 0;
}

static int ramfs_mknod(const char* path, mode_t mode, dev_t rdev)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    if (path == NULL)
        return -EIO;

    struct lookup_t* lookup;
    struct lookup_t* dir_lookup;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    size_t path_len = strlen(path);
    size_t dir_len  = util_dirname_len(path, path_len);

    printf("[%s]: Dir: \"%.*s\"\n", __func__, (int)dir_len, path);

    if (!find_lookupn(__func__, path, dir_len, _root_lookup, &dir_lookup))
        return -ENOENT;
    if (!(dir_lookup->inode_ptr->mode & S_IFDIR))
        return -ENOTDIR;
    if (find_lookupn(__func__, path, path_len, _root_lookup, &lookup))
        return -EEXIST;
    struct lookup_t* l1;
    if (!lookup_create(path, &l1))
        return -ENOSPC;

    printf("[%s]: file created, appending...\n", __func__);
    if (!lookup_append_lookup_as_child(dir_lookup, l1))
    {
        printf("[%s]: appending failed, free file\n", __func__);
        lookup_free_lookups(l1);
        return -EIO;
    }
    return 0;
}

static int ramfs_link(const char* oldpath, const char* newpath)
{
    printf("[%s]: Paths: \"%s\"->\"%s\"\n", __func__, oldpath, newpath);

    if (oldpath == NULL || newpath == NULL)
        return -EINVAL;

    struct lookup_t* lookup_old;
    struct lookup_t* lookup_new;
    struct lookup_t* dir_lookup;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    size_t path_len = strlen(newpath);
    size_t dir_len  = util_dirname_len(newpath, path_len);

    printf("[%s]: Dir: \"%.*s\"\n", __func__, (int)dir_len, newpath);

    if (!find_lookupn(__func__, oldpath, strlen(oldpath), _root_lookup, &lookup_old))
        return -ENOENT;
    if (!find_lookupn(__func__, newpath, dir_len, _root_lookup, &dir_lookup))
        return -ENOENT;
    if (!(dir_lookup->inode_ptr->mode & S_IFDIR))
        return -ENOTDIR;
    if (find_lookupn(__func__, newpath, path_len, _root_lookup, &lookup_new))
        return -EEXIST;

    if (!lookup_clone_lookup(newpath, lookup_old, &lookup_new))
        return -ENOSPC;

    printf("[%s]: file created, appending...\n", __func__);
    if (!lookup_append_lookup_as_child(dir_lookup, lookup_new))
    {
        printf("[%s]: appending failed, free file\n", __func__);
        lookup_free_lookups(lookup_new);
        return -EIO;
    }
    return 0;
}

static int ramfs_unlink(const char* path)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    struct lookup_t* lookup       = NULL;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (lookup != NULL || find_lookup(__func__, path, _root_lookup, &lookup))
    {
        if (lookup->inode_ptr->mode & S_IFDIR)
            return -EISDIR;
        if (!lookup_pluck_and_free_lookup(lookup))
            return -EIO;
        return 0;
    }
    else
        return -ENOENT;
}

static int ramfs_release(const char* path, struct fuse_file_info* fi)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    struct inode_t* inode = fi == NULL ? NULL : ((struct inode_t*)fi->fh);
    if (inode == NULL)
        return 0;
    inode->nrefs--;

    if (inode->nlink > 0 || inode->nrefs > 0)
        return 0;
    inode_free_inode(inode); /* This may or may not free the inode, we don't care */

    return 0;
}

#define SWAP_VAR(TYPE, VAR1, VAR2) \
    do                             \
    {                              \
        TYPE SWAP_TMP = VAR1;      \
        VAR1          = VAR2;      \
        VAR2          = SWAP_TMP;  \
    } while (0)

static int ramfs_rename(const char* oldpath, const char* newpath, unsigned int flags)
{
    if (flags & RENAME_EXCHANGE)
        printf("[%s]: \"%s\"<->\"%s\"\n", __func__, oldpath, newpath);
    else
        printf("[%s]: \"%s\"->\"%s\"\n", __func__, oldpath, newpath);

    if ((oldpath != NULL && strcmp(oldpath, "/") == 0) || (newpath != NULL && strcmp(oldpath, "/") == 0))
        return -EACCES;

    size_t oldpath_len = strlen(oldpath);
    size_t newpath_len = strlen(newpath);

    struct lookup_t* old_lookup   = NULL;
    struct lookup_t* new_lookup   = NULL;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    if ((flags & RENAME_EXCHANGE && flags & RENAME_NOREPLACE) || flags & RENAME_WHITEOUT)
        return -EINVAL;
    if (strcmp(oldpath, _root_lookup->basename) == 0)
        return -EACCES;

    if (!find_lookupn(__func__, oldpath, oldpath_len, _root_lookup, &old_lookup))
        return -ENOENT;
    find_lookupn(__func__, newpath, newpath_len, _root_lookup, &new_lookup);

    if (new_lookup != NULL)
    {
        if (!(old_lookup->inode_ptr->mode & S_IFDIR) && new_lookup->inode_ptr->mode & S_IFDIR)
            return -EISDIR;
        else if (!(new_lookup->inode_ptr->mode & S_IFDIR) && old_lookup->inode_ptr->mode & S_IFDIR)
            return -ENOTDIR;
    }

    if (flags & RENAME_EXCHANGE)
    {
        if (new_lookup == NULL)
            return -ENOENT;

        SWAP_VAR(struct inode_t*, old_lookup->inode_ptr, new_lookup->inode_ptr);

        inode_update_times(new_lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_METADATA);
    }
    else
    {
        struct lookup_t* new_dir_lookup  = NULL;
        size_t           newpath_dir_len = util_dirname_len(newpath, newpath_len);
        find_lookupn(__func__, newpath, newpath_dir_len, _root_lookup, &new_dir_lookup);
        if (new_lookup != NULL)
        {
            if (flags & RENAME_NOREPLACE)
                return -EEXIST;
            if (new_lookup->child != NULL)
                return -ENOTEMPTY;
            if (new_dir_lookup == NULL)
                return -EIO;
            lookup_pluck_and_free_lookup(new_lookup);
        }
        lookup_rename(old_lookup, newpath);
        if (lookup_pluck_lookup(old_lookup))
            lookup_append_lookup_as_child(new_dir_lookup, old_lookup);
    }
    inode_update_times(old_lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_METADATA);
    return 0;
}

static int ramfs_truncate(const char* path, off_t size, struct fuse_file_info* fi)
{
    struct inode_t*  inode        = fi == NULL ? NULL : ((struct inode_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    if (inode != NULL || find_inode(__func__, path, _root_lookup, &inode))
    {
        if (inode->mode & S_IFDIR)
            return -EISDIR;
        if (!inode_resize_buf(__func__, inode, size))
            return -ENOSPC;
        inode_update_times(inode, INODE_TIME_LEVEL_MODIFY_CONTENTS);
        return 0;
    }
    else
        return -ENOENT;
}

static int ramfs_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info* fi)
{
    printf("[%s]: Path: \"%s\", %d\n", __func__, path, (fi->flags & O_ACCMODE));

    struct inode_t*  inode        = fi == NULL ? NULL : ((struct inode_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    if (inode != NULL || find_inode(__func__, path, _root_lookup, &inode))
    {
        if (inode->mode & S_IFDIR)
            return -EISDIR;
        size_t msize = size + off;
        if (size == 0)
            return 0;
        if (!inode_resize_buf(__func__, inode, msize))
            return -ENOSPC;
        inode_update_times(inode, INODE_TIME_LEVEL_MODIFY_CONTENTS);
        memcpy(inode->buf + off, buf, size);
        inode->file_size = msize;
        return size;
    }
    else
        return -ENOENT;
}

static int ramfs_symlink(const char* target, const char* linkname)
{
    printf("[%s]: Paths: \"%s\"->\"%s\"\n", __func__, linkname, target);
    int ret = ramfs_mknod(linkname, 0, 0);
    if (ret != 0)
        return ret;

    struct inode_t*  inode        = NULL;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (find_inode(__func__, linkname, _root_lookup, &inode))
    {
        inode->mode -= S_IFREG;
        inode->mode |= S_IFLNK;
        struct fuse_file_info fi;
        memset(&fi, 0, sizeof(struct fuse_file_info));
        fi.fh = (uint64_t)inode;
        ramfs_write(linkname, target, strlen(target), 0, &fi);
        ANNOYING_PRINTF("[%s]: Link: \"%s\", file size: %zu\n", __func__, linkname, inode->file_size);
        ANNOYING_PRINTF("[%s]: Link: \"%s\", contents: %s\n", __func__, linkname, inode->buf);
        return 0;
    }
    return -EIO;
}

static int ramfs_readlink(const char* path, char* buf, size_t buf_size)
{
    printf("[%s]: Path: \"%s\", buf_size: %zu\n", __func__, path, buf_size);
    struct lookup_t* lookup       = NULL;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (!find_lookup(__func__, path, _root_lookup, &lookup))
        return -ENOENT;
    if (!(lookup->inode_ptr->mode & S_IFLNK))
        return -EINVAL;

    if (lookup->inode_ptr->buf != NULL)
    {
        inode_update_times(lookup->inode_ptr, INODE_TIME_LEVEL_ACCESS);
        size_t size = lookup->inode_ptr->file_size;
        if ((buf_size - 1) < size)
            size = buf_size - 1;
        memcpy(buf, lookup->inode_ptr->buf, size);
        buf[size] = 0;
        return 0;
    }
    else
        return -EIO;
}

static int ramfs_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    struct inode_t*  inode        = fi == NULL ? NULL : ((struct inode_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    if (inode == NULL && !find_inode(__func__, path, _root_lookup, &inode))
        return -ENOENT;

    struct timespec tv_access = tv[0];
    struct timespec tv_modify = tv[1];

    if (tv_access.tv_nsec == UTIME_OMIT && tv_modify.tv_nsec == UTIME_OMIT)
        return 0;

    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t))
        return -EIO;

    if (tv_access.tv_nsec == UTIME_NOW)
        tv_access = t;
    if (tv_modify.tv_nsec == UTIME_NOW)
        tv_modify = t;
    if (tv_access.tv_nsec == UTIME_OMIT)
        tv_access = inode->atime;
    if (tv_modify.tv_nsec == UTIME_OMIT)
        tv_modify = inode->mtime;

    inode->atime = tv_access;
    inode->ctime = tv_modify;

    inode_update_times(inode, INODE_TIME_LEVEL_MODIFY_METADATA);
    return 0;
}

static int ramfs_getattr(const char* path, struct stat* st, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    struct inode_t*  inode        = fi == NULL ? NULL : ((struct inode_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    memset(st, 0, sizeof(struct stat));
    if (inode == NULL && !find_inode(__func__, path, _root_lookup, &inode))
        return -ENOENT;

    /* In the future st_size for directories should reflect the size allocated to a child array */
    st->st_size  = inode->file_size;
    st->st_atim  = inode->atime;
    st->st_mtim  = inode->mtime;
    st->st_ctim  = inode->ctime;
    st->st_uid   = inode->uid;
    st->st_gid   = inode->gid;
    st->st_mode  = inode->mode;
    st->st_nlink = inode->nlink;
    st->st_ino   = inode->inode_num;

    /* Not particularly efficient, but works */
    struct lookup_t* lookup;
    if (inode->mode & S_IFDIR && find_lookup(__func__, path, _root_lookup, &lookup))
    {
        st->st_nlink++;
        lookup = lookup->child;
        while (lookup != NULL)
        {
            if (lookup->inode_ptr->mode & S_IFDIR)
                st->st_nlink++; /* Subdirs containing ".." count as hardlinks */
            lookup = lookup->next;
        }
    }
    return 0;
}

#ifdef ENABLE_STATX
static int ramfs_statx(const char* path, int flags, int mask, struct statx* stx, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    ANNOYING_PRINTF("[%s]: flags %d\n", __func__, flags);
    struct inode_t*  inode        = fi == NULL ? NULL : ((struct inode_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    memset(stx, 0, sizeof(struct statx));
    if (inode == NULL && !find_inode(__func__, path, _root_lookup, &inode))
        return -ENOENT;

#define TIMESPEC_TO_STX(STX_VAR, TS_VAR)  \
    do                                    \
    {                                     \
        STX_VAR.tv_sec  = TS_VAR.tv_sec;  \
        STX_VAR.tv_nsec = TS_VAR.tv_nsec; \
    } while (0)
    TIMESPEC_TO_STX(stx->stx_atime, inode->atime);
    TIMESPEC_TO_STX(stx->stx_mtime, inode->mtime);
    TIMESPEC_TO_STX(stx->stx_ctime, inode->ctime);
    TIMESPEC_TO_STX(stx->stx_btime, inode->btime);
    stx->stx_mask |= STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_BTIME;
#undef TIMESPEC_TO_STX
    stx->stx_uid   = inode->uid;
    stx->stx_gid   = inode->gid;
    stx->stx_mode  = inode->mode;
    stx->stx_nlink = inode->nlink;
    stx->stx_ino   = inode->inode_num;
    /* In the future stx_size for directories should reflect the size allocated to a child array */
    stx->stx_size = inode->file_size;
    stx->stx_mask |= STATX_UID | STATX_GID | STATX_MODE | STATX_NLINK | STATX_SIZE | STATX_INO;

    /* Not particularly efficient, but works */
    struct lookup_t* lookup;
    if (inode->mode & S_IFDIR && find_lookup(__func__, path, _root_lookup, &lookup))
    {
        stx->stx_nlink++;
        lookup = lookup->child;
        while (lookup != NULL)
        {
            if (lookup->inode_ptr->mode & S_IFDIR)
                stx->stx_nlink++; /* Subdirs containing ".." count as hardlinks */
            lookup = lookup->next;
        }
    }
    return 0;
}
#endif

static void* ramfs_init(struct fuse_conn_info* conn, struct fuse_config* cfg)
{
    TIME_BLOCK_START();
    printf("kernel_cache: %d, direct_io: %d, hard_remove: %d, use_ino: %d, \n", cfg->kernel_cache, cfg->direct_io, cfg->hard_remove, cfg->use_ino);
    cfg->kernel_cache = 0;
    cfg->direct_io    = 1;
    cfg->hard_remove  = 1;
    cfg->use_ino      = 1;
    printf("kernel_cache: %d, direct_io: %d, hard_remove: %d, use_ino: %d, \n", cfg->kernel_cache, cfg->direct_io, cfg->hard_remove, cfg->use_ino);

    struct filesystem_t* fs;

    fs = calloc(1, sizeof(struct filesystem_t));
    if (fs == NULL)
    {
        printf("Unable to create filesystem object!\n");
        exit(1);
        return NULL;
    }

    if (!lookup_create("/", &fs->root_lookup))
    {
        printf("Unable to create root file!\n");
        exit(1);
        return NULL;
    }

    fs->root_lookup->basename[0]      = '/';
    fs->root_lookup->inode_ptr->mode  = S_IFDIR | 0755;
    fs->root_lookup->inode_ptr->nlink = 1;

    lookup_create_blank_nodes_for_stress(fs->root_lookup, 4, 4);
    for (int i = 0; i < 2; i++)
        lookup_create_blank_nodes_for_stress(fs->root_lookup, 8, 2);

    double elapsed = 0.0;
    TIME_BLOCK_END(elapsed);
    printf("[%s]: Filesystem initialized in %fms\n", __func__, elapsed / 1000);
    return fs;
}

static void ramfs_destroy(void* _fs)
{
    struct filesystem_t* fs = _fs;
    TIME_BLOCK_START();
    printf("\n");
    lookup_print_tree(fs->root_lookup, 0);
    lookup_free_lookups_no_refs(fs->root_lookup);
    FREE(fs);
    double elapsed = 0.0;
    TIME_BLOCK_END(elapsed);
    printf("[%s]: Filesystem destroyed in %fms\n", __func__, elapsed / 1000);
}

static const struct fuse_operations ramfs_operations = {
    .readdir  = ramfs_readdir,
    .open     = ramfs_open,
    .read     = ramfs_read,
    .mknod    = ramfs_mknod,
    .link     = ramfs_link,
    .unlink   = ramfs_unlink,
    .release  = ramfs_release,
    .rename   = ramfs_rename,
    .write    = ramfs_write,
    .truncate = ramfs_truncate,
    .symlink  = ramfs_symlink,
    .readlink = ramfs_readlink,
    .utimens  = ramfs_utimens,
    .getattr  = ramfs_getattr,
/* As of 2024-09-21 libfuse statx support only exists in an yet to be merged github fork */
#ifdef ENABLE_STATX
    .statx = ramfs_statx,
#endif
    .init    = ramfs_init,
    .destroy = ramfs_destroy,
};

int main(int argc, char* argv[])
{
    /* KDevelop buffers the output and will not display anything */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

#ifdef __STDC_VERSION__
    printf("Built against C Standard: %ld\n", __STDC_VERSION__);
#endif
#ifdef ENABLE_STATX
    printf("statx(2) support enabled!\n");
#endif
    fflush(stdout);

    /* Not an elegant parser but it works */
    char** argv_fuse  = calloc(argc, sizeof(char*));
    int    argc_fuse  = 0;
    int    show_help  = 0;
    int    show_debug = 0;
    int    nofuse     = 0;

    if (argv_fuse == NULL)
    {
        printf("Argument parsing failure\n");
        return 1;
    }

    for (int i = 0; i < argc; i++)
    {
        char* arg = argv[i];
        if (strcmp("--ramfs-debug", arg) == 0)
            show_debug = 1;
        else if (strcmp("--ramfs-nofuse", arg) == 0)
            nofuse = 1;
        else
            argv_fuse[argc_fuse++] = arg;

        if ((strcmp("-h", arg) == 0 || strcmp("--help", arg) == 0))
            show_help = 1;
    }

    if (show_debug)
    {
        util_annoying_printf = printf;
        ANNOYING_PRINTF("util_annoying_printf set to printf\n");
    }

    if (show_help)
    {
        printf("\nUsage: %s [options] mountpoint\n", argv[0]);
        printf("Filesystem options:\n");
        printf("    --ramfs-debug       Enables all ramfs debug messages (ANNOYING_PRINTF)\n");
        printf("    --ramfs-nofuse      Initialize then immediately destroy filesystem\n\n");
        /* Setting argv[0] to a zero length string disables libfuse from printing another Usage string */
        argv_fuse[0][0] = 0;
    }

    if (nofuse)
    {
        struct fuse_config    fc;
        struct fuse_conn_info fci;
        ramfs_destroy(ramfs_init(&fci, &fc));
        free(argv_fuse);
        return 0;
    }

    int ret = fuse_main(argc_fuse, argv_fuse, &ramfs_operations, NULL);

    free(argv_fuse);

    return ret;
}
