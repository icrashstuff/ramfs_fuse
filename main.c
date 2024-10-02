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

    struct file_t* cur_file   = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (cur_file == NULL && !find_file(__func__, path, _root_file, &cur_file))
        return -ENOENT;

    if (!(cur_file->mode & S_IFDIR))
        return -ENOTDIR;

    filler(buf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    filler(buf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);

    if (cur_file->child == NULL)
        return 0;
    cur_file = cur_file->child;

    while (cur_file != NULL)
    {
        if (cur_file->name != NULL)
            filler(buf, util_basename(cur_file->name), NULL, 0, FUSE_FILL_DIR_DEFAULTS);
        cur_file = cur_file->next;
    }
    return 0;
}

static int ramfs_truncate(const char* path, off_t size, struct fuse_file_info* fi);
static int ramfs_open(const char* path, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);

    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (find_file(__func__, path, _root_file, (struct file_t**)&fi->fh))
    {
        if (((struct file_t*)fi->fh)->mode & S_IFDIR)
            return -EISDIR;
        ((struct file_t*)fi->fh)->nrefs++;
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

    struct file_t* file       = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (file == NULL && !find_file(__func__, path, _root_file, &file))
        return -ENOENT;
    if (file->mode & S_IFDIR)
        return -EISDIR;

    file_update_times(file, FILE_TIME_LEVEL_ACCESS);

    size_t offset = _offset;
    if (offset < file->file_size && file->buf != NULL)
    {
        if (offset + size > file->file_size)
            size = file->file_size - offset;
        memcpy(buf, &file->buf[offset], size);
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
    struct file_t* file;
    struct file_t* dir_file;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;

    size_t path_len = strlen(path);
    size_t dir_len  = util_dirname_len(path, path_len);

    printf("[%s]: Dir: \"%.*s\"\n", __func__, (int)dir_len, path);

    if (!find_filen(__func__, path, dir_len, _root_file, &dir_file))
        return -ENOENT;
    if (!(dir_file->mode & S_IFDIR))
        return -ENOTDIR;
    if (find_filen(__func__, path, path_len, _root_file, &file))
        return -EEXIST;
    struct file_t* f1;
    if (!file_create(path, &f1))
        return -ENOSPC;

    printf("[%s]: file created, appending...\n", __func__);
    if (!file_append_file_as_child(dir_file, f1))
    {
        printf("[%s]: appending failed, free file\n", __func__);
        file_free_files(f1);
        return -EIO;
    }
    return 0;
}

static int ramfs_unlink(const char* path)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    struct file_t* file       = NULL;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (file != NULL || find_file(__func__, path, _root_file, &file))
    {
        if (file->mode & S_IFDIR)
            return -EISDIR;
        if (--file->nlink > 0)
            return 0;
        if (!file_remove_file(file))
            return -EIO;
        if (file->nrefs == 0 && !file_free_files(file))
            return -EIO;
        return 0;
    }
    else
        return -ENOENT;
}

static int ramfs_release(const char* path, struct fuse_file_info* fi)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    struct file_t* file = (struct file_t*)fi->fh;
    if (file == NULL)
        return 0;
    file->nrefs--;

    if (file->nlink > 0 || file->nrefs > 0)
        return 0;
    file_remove_file(file); /* Make sure file is removed from a list */
    file_free_files(file);

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

    size_t oldpath_len     = strlen(oldpath);
    size_t newpath_len     = strlen(newpath);
    size_t oldpath_dir_len = util_dirname_len(oldpath, oldpath_len);
    size_t newpath_dir_len = util_dirname_len(newpath, newpath_len);

    /* Temporary check to disable cross directory renaming */
    if (oldpath_dir_len != newpath_dir_len && strncmp(oldpath, newpath, oldpath_len))
        return -EINVAL;

    struct file_t* old_file   = NULL;
    struct file_t* new_file   = NULL;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;

    if ((flags & RENAME_EXCHANGE && flags & RENAME_NOREPLACE) || flags & RENAME_WHITEOUT)
        return -EINVAL;
    if (strcmp(oldpath, _root_file->name) == 0)
        return -EACCES;

    if (!find_filen(__func__, oldpath, oldpath_len, _root_file, &old_file))
        return -ENOENT;
    find_filen(__func__, newpath, newpath_len, _root_file, &new_file);

    /* Temporary check to disable directory renaming */
    if (old_file->mode & S_IFDIR)
        return -EINVAL;
    if (new_file != NULL && new_file->mode & S_IFDIR)
        return -EINVAL;

    if (flags & RENAME_NOREPLACE && new_file != NULL)
    {
        if (new_file != NULL)
            return -EEXIST;

        if (!file_rename(old_file, newpath))
            return -ENOMEM;
    }
    else if (flags & RENAME_EXCHANGE)
    {
        if (new_file == NULL)
            return -ENOENT;

        SWAP_VAR(char*, old_file->name, new_file->name);
        SWAP_VAR(size_t, old_file->name_buf_size, new_file->name_buf_size);

        file_update_times(new_file, FILE_TIME_LEVEL_MODIFY_METADATA);
    }
    else
    {
        if (!file_rename(old_file, newpath))
            return -ENOMEM;
        if (new_file != NULL)
            if (file_remove_file(new_file) && --new_file->nlink > 0 && --new_file->nrefs > 0)
                file_free_files(new_file);
    }
    file_update_times(old_file, FILE_TIME_LEVEL_MODIFY_METADATA);
    return 0;
}

static int ramfs_truncate(const char* path, off_t size, struct fuse_file_info* fi)
{
    struct file_t* file       = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;

    if (file != NULL || find_file(__func__, path, _root_file, &file))
    {
        if (file->mode & S_IFDIR)
            return -EISDIR;
        if (!file_resize_buf(__func__, file, size))
            return -ENOSPC;
        file_update_times(file, FILE_TIME_LEVEL_MODIFY_CONTENTS);
        return 0;
    }
    else
        return -ENOENT;
}

static int ramfs_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info* fi)
{
    printf("[%s]: Path: \"%s\", %d\n", __func__, path, (fi->flags & O_ACCMODE));
    (void)fi;
    struct file_t* file       = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;

    if ((file != NULL || find_file(__func__, path, _root_file, &file)))
    {
        if (file->mode & S_IFDIR)
            return -EISDIR;
        size_t msize = size + off;
        if (size == 0)
            return 0;
        if (!file_resize_buf(__func__, file, msize))
            return -ENOSPC;
        file_update_times(file, FILE_TIME_LEVEL_MODIFY_CONTENTS);
        memcpy(file->buf + off, buf, size);
        file->file_size = msize;
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

    struct file_t* file       = NULL;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (find_file(__func__, linkname, _root_file, &file))
    {
        file->mode -= S_IFREG;
        file->mode |= S_IFLNK;
        struct fuse_file_info fi;
        memset(&fi, 0, sizeof(struct fuse_file_info));
        fi.fh = (uint64_t)file;
        ramfs_write(linkname, target, strlen(target), 0, &fi);
        ANNOYING_PRINTF("[%s]: Link: \"%s\", file size: %zu\n", __func__, linkname, file->file_size);
        ANNOYING_PRINTF("[%s]: Link: \"%s\", contents: %s\n", __func__, linkname, file->buf);
        return 0;
    }
    return -EIO;
}

static int ramfs_readlink(const char* path, char* buf, size_t buf_size)
{
    printf("[%s]: Path: \"%s\", buf_size: %zu\n", __func__, path, buf_size);
    struct file_t* file       = NULL;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (!find_file(__func__, path, _root_file, &file))
        return -ENOENT;
    if (!(file->mode & S_IFLNK))
        return -EINVAL;

    if (file->buf != NULL)
    {
        file_update_times(file, FILE_TIME_LEVEL_ACCESS);
        size_t size = file->file_size;
        if ((buf_size - 1) < size)
            size = buf_size - 1;
        memcpy(buf, file->buf, size);
        buf[size] = 0;
        return 0;
    }
    else
        return -EIO;
}

static int ramfs_getattr(const char* path, struct stat* st, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    struct file_t* file       = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;

    memset(st, 0, sizeof(struct stat));
    if (file == NULL && !find_file(__func__, path, _root_file, &file))
        return -ENOENT;

    /* In the future st_size for directories should reflect the size allocated to a child array */
    st->st_size  = file->file_size;
    st->st_atim  = file->atime;
    st->st_mtim  = file->mtime;
    st->st_ctim  = file->ctime;
    st->st_uid   = file->uid;
    st->st_gid   = file->gid;
    st->st_mode  = file->mode;
    st->st_nlink = file->nlink;

    /* Not particularly efficient, but works */
    file = file->child;
    while (file != NULL)
    {
        if (file->mode & S_IFDIR)
            st->st_nlink++; /* Subdirs containing ".." count as hardlinks */
        file = file->next;
    }
    return 0;
}

#ifdef ENABLE_STATX
static int ramfs_statx(const char* path, int flags, int mask, struct statx* stx, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    ANNOYING_PRINTF("[%s]: flags %d\n", __func__, flags);
    struct file_t* file       = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;

    memset(stx, 0, sizeof(struct stat));
    if (file == NULL && !find_file(__func__, path, _root_file, &file))
        return -ENOENT;

#define TIMESPEC_TO_STX(STX_VAR, TS_VAR)  \
    do                                    \
    {                                     \
        STX_VAR.tv_sec  = TS_VAR.tv_sec;  \
        STX_VAR.tv_nsec = TS_VAR.tv_nsec; \
    } while (0)
    TIMESPEC_TO_STX(stx->stx_atime, file->atime);
    TIMESPEC_TO_STX(stx->stx_mtime, file->mtime);
    TIMESPEC_TO_STX(stx->stx_ctime, file->ctime);
    TIMESPEC_TO_STX(stx->stx_btime, file->btime);
    stx->stx_mask |= STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_BTIME;
#undef TIMESPEC_TO_STX
    stx->stx_uid   = file->uid;
    stx->stx_gid   = file->gid;
    stx->stx_mode  = file->mode;
    stx->stx_nlink = file->nlink;
    /* In the future stx_size for directories should reflect the size allocated to a child array */
    stx->stx_size = file->file_size;
    stx->stx_mask |= STATX_UID | STATX_GID | STATX_MODE | STATX_NLINK | STATX_SIZE;

    /* Not particularly efficient, but works */
    file = file->child;
    while (file != NULL)
    {
        if (file->mode & S_IFDIR)
            stx->stx_nlink++; /* Subdirs containing ".." count as hardlinks */
        file = file->next;
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

    if (!file_create("/", &fs->root_file))
    {
        printf("Unable to create root file!\n");
        exit(1);
        return NULL;
    }

    fs->root_file->mode  = S_IFDIR | 0755;
    fs->root_file->nlink = 2;
    file_create_blank_nodes_for_stress(fs->root_file, 4, 4);
    file_create_blank_nodes_for_stress(fs->root_file, 4, 4);
    double elapsed = 0.0;
    TIME_BLOCK_END(elapsed);
    printf("[%s]: Filesystem initialized in %fms\n", __func__, elapsed / 1000);
    return fs;
}

static void ramfs_destroy(void* _fs)
{
    struct filesystem_t* fs = _fs;
    printf("\n");
    file_print_tree(fs->root_file, 0);
    file_free_files(fs->root_file);
    FREE(fs);
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
