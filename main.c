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

    struct lookup_t* cur_lookup   = fi == NULL ? NULL : ((struct lookup_t*)fi->fh);
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
    if (find_lookup(__func__, path, _root_lookup, (struct lookup_t**)&fi->fh))
    {
        if (((struct lookup_t*)fi->fh)->inode_ptr->mode & S_IFDIR)
            return -EISDIR;
        ((struct lookup_t*)fi->fh)->inode_ptr->nrefs++;
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

    struct lookup_t* lookup       = fi == NULL ? NULL : ((struct lookup_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (lookup == NULL && !find_lookup(__func__, path, _root_lookup, &lookup))
        return -ENOENT;
    if (lookup->inode_ptr->mode & S_IFDIR)
        return -EISDIR;

    inode_update_times(lookup->inode_ptr, INODE_TIME_LEVEL_ACCESS);

    size_t offset = _offset;
    if (offset < lookup->inode_ptr->file_size && lookup->inode_ptr->buf != NULL)
    {
        if (offset + size > lookup->inode_ptr->file_size)
            size = lookup->inode_ptr->file_size - offset;
        memcpy(buf, &lookup->inode_ptr->buf[offset], size);
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

static int ramfs_unlink(const char* path)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    struct lookup_t* lookup       = NULL;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (lookup != NULL || find_lookup(__func__, path, _root_lookup, &lookup))
    {
        if (lookup->inode_ptr->mode & S_IFDIR)
            return -EISDIR;
        if (--lookup->inode_ptr->nlink > 0)
            return 0;
        if (!lookup_pluck_lookup(lookup))
            return -EIO;
        if (lookup->inode_ptr->nrefs == 0 && !lookup_free_lookups(lookup))
            return -EIO;
        return 0;
    }
    else
        return -ENOENT;
}

static int ramfs_release(const char* path, struct fuse_file_info* fi)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    struct lookup_t* lookup = (struct lookup_t*)fi->fh;
    if (lookup == NULL)
        return 0;
    lookup->inode_ptr->nrefs--;

    if (lookup->inode_ptr->nlink > 0 || lookup->inode_ptr->nrefs > 0)
        return 0;
    lookup_pluck_lookup(lookup); /* Make doubly sure that the lookup is removed from the list */
    lookup_free_lookups(lookup);

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
    printf("[%s]: \"%s\"->\"%s\"\n", __func__, oldpath, newpath);

    if ((oldpath != NULL && strcmp(oldpath, "/") == 0) || (newpath != NULL && strcmp(oldpath, "/") == 0))
        return -EPERM;

    size_t oldpath_len     = strlen(oldpath);
    size_t newpath_len     = strlen(newpath);
    size_t oldpath_dir_len = util_dirname_len(oldpath, oldpath_len);
    size_t newpath_dir_len = util_dirname_len(newpath, newpath_len);

    /* Temporary check to disable cross directory renaming */
    if (oldpath_dir_len != newpath_dir_len && strncmp(oldpath, newpath, oldpath_len))
        return -EINVAL;

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

    /* Temporary check to disable directory renaming */
    if (old_lookup->inode_ptr->mode & S_IFDIR)
        return -EINVAL;
    if (new_lookup != NULL && new_lookup->inode_ptr->mode & S_IFDIR)
        return -EINVAL;

    if (flags & RENAME_NOREPLACE && new_lookup != NULL)
    {
        if (new_lookup != NULL)
            return -EEXIST;

        if (!lookup_rename(old_lookup, newpath))
            return -ENOMEM;
    }
    else if (flags & RENAME_EXCHANGE)
    {
        if (new_lookup == NULL)
            return -ENOENT;

        SWAP_VAR(struct inode_t*, old_lookup->inode_ptr, new_lookup->inode_ptr);

        inode_update_times(new_lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_METADATA);
    }
    else
    {
        if (!lookup_rename(old_lookup, newpath))
            return -ENOMEM;
        if (new_lookup != NULL)
            if (lookup_pluck_lookup(new_lookup) && --new_lookup->inode_ptr->nlink > 0 && --new_lookup->inode_ptr->nrefs > 0)
                lookup_free_lookups(new_lookup);
    }
    inode_update_times(old_lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_METADATA);
    return 0;
}

static int ramfs_truncate(const char* path, off_t size, struct fuse_file_info* fi)
{
    struct lookup_t* lookup       = fi == NULL ? NULL : ((struct lookup_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    if (lookup != NULL || find_lookup(__func__, path, _root_lookup, &lookup))
    {
        if (lookup->inode_ptr->mode & S_IFDIR)
            return -EISDIR;
        if (!inode_resize_buf(__func__, lookup->inode_ptr, size))
            return -ENOSPC;
        inode_update_times(lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_CONTENTS);
        return 0;
    }
    else
        return -ENOENT;
}

static int ramfs_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info* fi)
{
    printf("[%s]: Path: \"%s\", %d\n", __func__, path, (fi->flags & O_ACCMODE));
    (void)fi;
    struct lookup_t* lookup       = fi == NULL ? NULL : ((struct lookup_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    if ((lookup != NULL || find_lookup(__func__, path, _root_lookup, &lookup)))
    {
        if (lookup->inode_ptr->mode & S_IFDIR)
            return -EISDIR;
        size_t msize = size + off;
        if (size == 0)
            return 0;
        if (!inode_resize_buf(__func__, lookup->inode_ptr, msize))
            return -ENOSPC;
        inode_update_times(lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_CONTENTS);
        memcpy(lookup->inode_ptr->buf + off, buf, size);
        lookup->inode_ptr->file_size = msize;
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

    struct lookup_t* lookup       = NULL;
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;
    if (find_lookup(__func__, linkname, _root_lookup, &lookup))
    {
        lookup->inode_ptr->mode -= S_IFREG;
        lookup->inode_ptr->mode |= S_IFLNK;
        struct fuse_file_info fi;
        memset(&fi, 0, sizeof(struct fuse_file_info));
        fi.fh = (uint64_t)lookup;
        ramfs_write(linkname, target, strlen(target), 0, &fi);
        ANNOYING_PRINTF("[%s]: Link: \"%s\", file size: %zu\n", __func__, linkname, lookup->inode_ptr->file_size);
        ANNOYING_PRINTF("[%s]: Link: \"%s\", contents: %s\n", __func__, linkname, lookup->inode_ptr->buf);
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
    struct lookup_t* lookup       = fi == NULL ? NULL : ((struct lookup_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    if (lookup == NULL && !find_lookup(__func__, path, _root_lookup, &lookup))
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
        tv_access = lookup->inode_ptr->atime;
    if (tv_modify.tv_nsec == UTIME_OMIT)
        tv_modify = lookup->inode_ptr->mtime;

    lookup->inode_ptr->atime = tv_access;
    lookup->inode_ptr->ctime = tv_modify;

    inode_update_times(lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_METADATA);
    return 0;
}

static int ramfs_getattr(const char* path, struct stat* st, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    struct lookup_t* lookup       = fi == NULL ? NULL : ((struct lookup_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    memset(st, 0, sizeof(struct stat));
    if (lookup == NULL && !find_lookup(__func__, path, _root_lookup, &lookup))
        return -ENOENT;

    /* In the future st_size for directories should reflect the size allocated to a child array */
    st->st_size  = lookup->inode_ptr->file_size;
    st->st_atim  = lookup->inode_ptr->atime;
    st->st_mtim  = lookup->inode_ptr->mtime;
    st->st_ctim  = lookup->inode_ptr->ctime;
    st->st_uid   = lookup->inode_ptr->uid;
    st->st_gid   = lookup->inode_ptr->gid;
    st->st_mode  = lookup->inode_ptr->mode;
    st->st_nlink = lookup->inode_ptr->nlink;

    /* Not particularly efficient, but works */
    lookup = lookup->child;
    while (lookup != NULL)
    {
        if (lookup->inode_ptr->mode & S_IFDIR)
            st->st_nlink++; /* Subdirs containing ".." count as hardlinks */
        lookup = lookup->next;
    }
    return 0;
}

#ifdef ENABLE_STATX
static int ramfs_statx(const char* path, int flags, int mask, struct statx* stx, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    ANNOYING_PRINTF("[%s]: flags %d\n", __func__, flags);
    struct lookup_t* lookup       = fi == NULL ? NULL : ((struct lookup_t*)fi->fh);
    struct lookup_t* _root_lookup = get_filesytem_from_fuse_context()->root_lookup;

    memset(stx, 0, sizeof(struct stat));
    if (lookup == NULL && !find_lookup(__func__, path, _root_lookup, &lookup))
        return -ENOENT;

#define TIMESPEC_TO_STX(STX_VAR, TS_VAR)  \
    do                                    \
    {                                     \
        STX_VAR.tv_sec  = TS_VAR.tv_sec;  \
        STX_VAR.tv_nsec = TS_VAR.tv_nsec; \
    } while (0)
    TIMESPEC_TO_STX(stx->stx_atime, lookup->inode_ptr->atime);
    TIMESPEC_TO_STX(stx->stx_mtime, lookup->inode_ptr->mtime);
    TIMESPEC_TO_STX(stx->stx_ctime, lookup->inode_ptr->ctime);
    TIMESPEC_TO_STX(stx->stx_btime, lookup->inode_ptr->btime);
    stx->stx_mask |= STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_BTIME;
#undef TIMESPEC_TO_STX
    stx->stx_uid   = lookup->inode_ptr->uid;
    stx->stx_gid   = lookup->inode_ptr->gid;
    stx->stx_mode  = lookup->inode_ptr->mode;
    stx->stx_nlink = lookup->inode_ptr->nlink;
    /* In the future stx_size for directories should reflect the size allocated to a child array */
    stx->stx_size = lookup->inode_ptr->file_size;
    stx->stx_mask |= STATX_UID | STATX_GID | STATX_MODE | STATX_NLINK | STATX_SIZE;

    /* Not particularly efficient, but works */
    lookup = lookup->child;
    while (lookup != NULL)
    {
        if (lookup->inode_ptr->mode & S_IFDIR)
            stx->stx_nlink++; /* Subdirs containing ".." count as hardlinks */
        lookup = lookup->next;
    }
    return 0;
}
#endif

static void* ramfs_init(struct fuse_conn_info* conn, struct fuse_config* cfg)
{
    TIME_BLOCK_START();
    printf("kernel_cache: %d, direct_io: %d, hard_remove: %d\n", cfg->kernel_cache, cfg->direct_io, cfg->hard_remove);
    cfg->kernel_cache = 0;
    cfg->direct_io    = 1;
    cfg->hard_remove  = 1;
    printf("kernel_cache: %d, direct_io: %d, hard_remove: %d\n", cfg->kernel_cache, cfg->direct_io, cfg->hard_remove);

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
    fs->root_lookup->inode_ptr->nlink = 2;

    lookup_create_blank_nodes_for_stress(fs->root_lookup, 4, 4);
    for (int i = 0; i < 2; i++)
        lookup_create_blank_nodes_for_stress(fs->root_lookup, 8, 64);

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
    lookup_free_lookups(fs->root_lookup);
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

    if (argv_fuse == NULL)
    {
        printf("Argument parsing failure\n");
        return 1;
    }

    for (int i = 0; i < argc; i++)
    {
        char* arg = argv[i];
        if (strcmp("--debug-ramfs", arg) == 0)
            show_debug = 1;
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
        printf("    --debug-ramfs       Enables all ramfs debug messages (ANNOYING_PRINTF)\n\n");
        /* Setting argv[0] to a zero length string disables libfuse from printing another Usage string */
        argv_fuse[0][0] = 0;
    }

    int ret = fuse_main(argc_fuse, argv_fuse, &ramfs_operations, NULL);

    free(argv_fuse);

    return ret;
}
