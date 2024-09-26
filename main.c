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

#define FILE_BUF_SIZE_ALIGN 4096
/* When the buffer is below this percentage, shrink the buffer */
#define FILE_BUF_SIZE_SHRINK_PERCENTAGE 50

#if 0
#define ANNOYING_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define ANNOYING_PRINTF(fmt, ...)
#endif

#define TIME_BLOCK_START()        \
    struct timespec __start_time; \
    clock_gettime(CLOCK_MONOTONIC, &__start_time);
#define TIME_BLOCK_END(var)                                                                                                      \
    do                                                                                                                           \
    {                                                                                                                            \
        struct timespec __end_time;                                                                                              \
        clock_gettime(CLOCK_MONOTONIC, &__end_time);                                                                             \
        var = (((__end_time.tv_sec - __start_time.tv_sec) * 1000000000) + (__end_time.tv_nsec - __start_time.tv_nsec)) / 1000.0; \
    } while (0)

#define FREE(ptr)        \
    do                   \
    {                    \
        if (ptr != NULL) \
        {                \
            free(ptr);   \
            ptr = NULL;  \
        }                \
    } while (0)

struct file_t
{
    char*  name;
    size_t name_buf_size;

    struct file_t* prev;
    struct file_t* next;

    size_t buf_size;
    size_t file_size;
    char*  buf;

    /**
     * Access time
     * Because this is a ramfs we will update this every time
     * the contents of buf are modified, read, or created
     *
     *
     *
     * see strictatime and relatime fs mount options for future ideas
     */
    struct timespec atime;
    /** Metadata Modification time (also includes non-zero calls to write) */
    struct timespec ctime;
    /** Content Modification time */
    struct timespec mtime;
    /** File_t creation time (should not be changed) */
    struct timespec btime;

    uid_t uid;
    gid_t gid;

    mode_t mode;
    /**
     * Number of hard links to file, in the case of directories there is the . directory which increases the value to 1
     * If nlink and refs both hit 0, then delete (this will be important when and if hardlinks are implemented)
     */
    nlink_t nlink;
    /**
     * Number of unreleased open() calls to the files
     * If nlink and refs both hit 0, then the file can be deleted (this will be important when and if hardlinks are implemented)
     */
    size_t nrefs;
};

struct filesystem_t
{
    struct file_t* root_file;
};

/**
 * Values that control which time fields will be updated by file_update_times
 */
enum file_time_update_level_t
{
    FILE_TIME_LEVEL_ACCESS          = 0,
    FILE_TIME_LEVEL_MODIFY_METADATA = 1,
    FILE_TIME_LEVEL_MODIFY_CONTENTS = 2,
    FILE_TIME_LEVEL_CREATION        = 3,
};

/**
 * Helper function to update appropriate file times
 *
 * Returns 1 on success and 0 on failure
 */
static int file_update_times(struct file_t* file, enum file_time_update_level_t level)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t))
        return 0;
    switch (level)
    {
    case FILE_TIME_LEVEL_CREATION:
        file->btime = t;
        /* FALLTHRU */
    case FILE_TIME_LEVEL_MODIFY_CONTENTS:
        file->mtime = t;
        file->ctime = t; /* Contents being modified counts as a metadata change, I think */
        /* FALLTHRU */
    case FILE_TIME_LEVEL_ACCESS:
        file->atime = t;
        break;
    case FILE_TIME_LEVEL_MODIFY_METADATA:
        file->ctime = t;
        break;
    default:
        return 0;
    }
    return 1;
}

/* Finds a file by recursing through the linked list, sets found_file and returns true if name found */
int _find_file(size_t recur_level, const char* caller, const char* name, struct file_t* first_file, struct file_t** found_file)
{
    if (first_file == NULL || name == NULL || found_file == NULL || strlen(name) == 0)
        return 0;
    if (first_file->name != NULL && strcmp(first_file->name, name) == 0)
    {
        ANNOYING_PRINTF("[%s][%s]: found file \"%s\", level: %zu\n", caller, __func__, name, recur_level);
        *found_file = first_file;
        return 1;
    }
    if (first_file->next != NULL)
    {
        return _find_file(recur_level + 1, caller, name, first_file->next, found_file);
    }
    printf("[%s][%s]: did not find file \"%s\"\n", caller, __func__, name);
    return 0;
}

int find_file(const char* caller, const char* name, struct file_t* first_file, struct file_t** found_file)
{
    struct timespec start_time;
    if (clock_gettime(CLOCK_MONOTONIC, &start_time))
        return _find_file(0, caller, name, first_file, found_file);
    int             ret = _find_file(0, caller, name, first_file, found_file);
    struct timespec end_time;
    if (clock_gettime(CLOCK_MONOTONIC, &end_time))
        return ret;
    ANNOYING_PRINTF("[%s][%s]: Path: \"%s\", time: %fus\n", caller, __func__, name,
        (((end_time.tv_sec - start_time.tv_sec) * 1000000000) + (end_time.tv_nsec - start_time.tv_nsec)) / 1000.0);
    return ret;
}

int append_file(struct file_t* first_file, struct file_t* new_file)
{
    if (first_file == NULL || new_file == NULL)
        return 0;
    struct file_t* cur_file = first_file;
    while (cur_file->next != NULL)
        cur_file = cur_file->next;
    cur_file->next = new_file;
    new_file->prev = cur_file;
    new_file->next = NULL;
    return 1;
}

/**
 * Removes a file from the a file_t linked list
 * Returns 1 on success and 0 on failure
 */
int remove_file(struct file_t* file)
{
    if (file == NULL)
        return 0;

    if (file->next != NULL)
        file->next->prev = file->prev;
    if (file->prev != NULL)
        file->prev->next = file->next;
    file->next = NULL;
    file->prev = NULL;

    return 1;
}

/**
 * Frees a file and all following file_t->next entries
 * Returns 1 on success and 0 on failure
 */
int free_files(struct file_t* first_file)
{
    if (first_file == NULL)
        return 0;
    struct file_t* next_file = first_file->next;
    FREE(first_file->name);
    FREE(first_file->buf);
    FREE(first_file);
    if (next_file != NULL)
        return free_files(next_file);
    return 1;
}

int file_resize_buf(const char* caller, struct file_t* file, size_t req_size)
{
    if (file == NULL)
        return 0;
    size_t size = 0;
    if (req_size != 0)
        size = ((req_size / FILE_BUF_SIZE_ALIGN) + 1) * FILE_BUF_SIZE_ALIGN;
    printf("[%s][%s]: Resize \"%s\" size(buf): %zu(%zu)->%zu(%zu)\n", caller, __func__, file->name, file->file_size, file->buf_size, req_size, size);

    if (size == 0)
    {
        FREE(file->buf);
        file->buf_size  = 0;
        file->file_size = 0;
        return 1;
    }

    if (file->buf_size < size || size < (file->buf_size * FILE_BUF_SIZE_SHRINK_PERCENTAGE / 100))
    {
        char* new_ptr;
        if (file->buf != NULL)
            new_ptr = realloc(file->buf, size);
        else
            new_ptr = calloc(size, sizeof(char));
        if (new_ptr == NULL)
            return 0;
        file->buf_size = size;
        file->buf      = new_ptr;
        if (file->file_size < size)
        {
            size_t diff = size - file->file_size;
            memset(&file->buf[file->file_size], 0, diff);
        }
    }

    file->file_size = req_size;
    return 1;
}

/**
 * Renames a file, does not check to see if this causes a conflict.
 *
 * Returns 1 on success and 0 on failure
 */
int file_rename(struct file_t* file, const char* new_name)
{
    if (file == NULL)
        return 0;
    size_t old_name_len = 0;
    size_t new_name_len = strlen(new_name);
    if (file->name != NULL)
        old_name_len = file->name_buf_size;

    if (new_name_len == 0)
    {
        FREE(file->name);
        file->name_buf_size = 0;
        return 1;
    }
    else if (old_name_len < new_name_len)
    {
        char* new_name_buf = calloc(new_name_len, sizeof(char));
        char* old_name_buf = file->name;
        if (new_name_buf == NULL)
            return 0;
        memcpy(new_name_buf, new_name, new_name_len);
        file->name = new_name_buf;
        FREE(old_name_buf);
        return 1;
    }
    else if (new_name_len < old_name_len)
    {
        memcpy(file->name, new_name, new_name_len);
        return 1;
    }
    return 0;
}

int create_file(const char* name, struct file_t** file_ptr)
{
    if (file_ptr == NULL)
        return 0;
    struct file_t* file = calloc(1, sizeof(struct file_t));
    if (file == NULL)
        return 0;
    if (!file_rename(file, name))
        return 0;
    file_resize_buf(__func__, file, 0);
    file_update_times(file, FILE_TIME_LEVEL_CREATION);
    file->uid   = getuid();
    file->gid   = getuid();
    file->mode  = S_IFREG | 0755;
    file->nlink = 1;

    *file_ptr = file;
    return 1;
}

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
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);

    if (path == NULL || strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    filler(buf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    struct file_t* cur_file = get_filesytem_from_fuse_context()->root_file;
    while (cur_file->next != NULL)
    {
        cur_file = cur_file->next;
        if (cur_file->name != NULL)
            filler(buf, cur_file->name, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    }
    return 0;
}

static int ramfs_truncate(const char* path, off_t size, struct fuse_file_info* fi);
static int ramfs_open(const char* path, struct fuse_file_info* fi)
{
    ANNOYING_PRINTF("[%s]: Path: \"%s\"\n", __func__, path);
    if (path != NULL && strcmp(path, "/") == 0)
        return -EISDIR;

    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (find_file(__func__, &path[1], _root_file, (struct file_t**)&fi->fh))
        ((struct file_t*)fi->fh)->nrefs++;
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
    if (path != NULL && strcmp(path, "/") == 0)
        return -EISDIR;

    struct file_t* file       = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (file == NULL && !find_file(__func__, &path[1], _root_file, &file))
        return -ENOENT;

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
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (find_file(__func__, &path[1], _root_file, &file))
        return -EEXIST;
    struct file_t* f1;
    if (!create_file(&path[1], &f1))
        return -ENOSPC;

    printf("[%s]: file created, appending...\n", __func__);
    if (!append_file(_root_file, f1))
    {
        printf("[%s]: appending failed, free file\n", __func__);
        free_files(f1);
        return -EIO;
    }
    return 0;
}

static int ramfs_unlink(const char* path)
{
    printf("[%s]: Path: \"%s\"\n", __func__, path);
    struct file_t* file       = NULL;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (path != NULL && strcmp(path, "/") == 0)
        return -EISDIR;
    else if (file != NULL || find_file(__func__, &path[1], _root_file, &file))
    {
        if (--file->nlink > 0)
            return 0;
        if (!remove_file(file))
            return -EIO;
        if (file->nrefs == 0 && !free_files(file))
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
    remove_file(file); /* Make sure file is removed from a list */
    free_files(file);

    return 0;
}

static int ramfs_rename(const char* oldpath, const char* newpath, unsigned int flags)
{
    printf("[%s]: \"%s\"->\"%s\"\n", __func__, oldpath, newpath);
    struct file_t* old_file   = NULL;
    struct file_t* new_file   = NULL;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;

    if ((flags & RENAME_EXCHANGE && flags & RENAME_NOREPLACE) || flags & RENAME_WHITEOUT)
        return -EINVAL;
    if (strcmp(oldpath, "/") == 0)
        return -EACCES;

    if (!find_file(__func__, &oldpath[1], _root_file, &old_file))
        return -ENOENT;
    find_file(__func__, &newpath[1], _root_file, &new_file);

    if (flags & RENAME_NOREPLACE && new_file != NULL)
    {
        if (new_file != NULL)
            return -EEXIST;
        if (!file_rename(old_file, &newpath[1]))
            return -ENOMEM;
    }
    else if (flags & RENAME_EXCHANGE)
    {
        if (new_file == NULL)
            return -ENOENT;
        char* oldname  = old_file->name;
        old_file->name = new_file->name;
        new_file->name = oldname;
        file_update_times(new_file, FILE_TIME_LEVEL_MODIFY_METADATA);
    }
    else
    {
        if (!file_rename(old_file, &newpath[1]))
            return -ENOMEM;
        if (new_file != NULL)
            if (remove_file(new_file) && --new_file->nlink > 0 && --new_file->nrefs > 0)
                free_files(new_file);
    }
    file_update_times(old_file, FILE_TIME_LEVEL_MODIFY_METADATA);
    return 0;
}

static int ramfs_truncate(const char* path, off_t size, struct fuse_file_info* fi)
{
    struct file_t* file       = fi == NULL ? NULL : ((struct file_t*)fi->fh);
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (path != NULL && strcmp(path, "/") == 0)
        return -EISDIR;
    else if (file != NULL || find_file(__func__, &path[1], _root_file, &file))
    {
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

    if (path != NULL && strcmp(path, "/") == 0)
    {
        return -EISDIR;
    }
    else if (file != NULL || find_file(__func__, &path[1], _root_file, &file))
    {
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
    if (find_file(__func__, &linkname[1], _root_file, &file))
    {
        file->mode -= S_IFREG;
        file->mode |= S_IFLNK;
        struct fuse_file_info fi;
        memset(&fi, 0, sizeof(struct fuse_file_info));
        fi.fh = (uint64_t)file;
        ramfs_write(linkname, target, strlen(target), 0, &fi);
        printf("%zu\n", file->file_size);
        printf("%s\n", file->buf);
        return 0;
    }
    return -EIO;
}

static int ramfs_readlink(const char* path, char* buf, size_t buf_size)
{
    printf("[%s]: Path: \"%s\", buf_size: %zu\n", __func__, path, buf_size);
    struct file_t* file       = NULL;
    struct file_t* _root_file = get_filesytem_from_fuse_context()->root_file;
    if (!find_file(__func__, &path[1], _root_file, &file))
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
    if (path != NULL && strcmp(path, "/") == 0)
        file = _root_file;
    else if (file != NULL || find_file(__func__, &path[1], _root_file, &file))
        st->st_size = file->file_size;
    else
        return -ENOENT;

    st->st_atim  = file->atime;
    st->st_mtim  = file->mtime;
    st->st_ctim  = file->ctime;
    st->st_uid   = file->uid;
    st->st_gid   = file->gid;
    st->st_mode  = file->mode;
    st->st_nlink = file->nlink;

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
    if (path != NULL && strcmp(path, "/") == 0)
        file = _root_file;
    else if (file != NULL || find_file(__func__, &path[1], _root_file, &file))
    {
        stx->stx_size = file->file_size;
        stx->stx_mask |= STATX_SIZE;
    }
    else
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
    stx->stx_mask |= STATX_UID | STATX_GID | STATX_MODE | STATX_NLINK;

    return 0;
}
#endif

/* This is only meant to be used when initializing the filesystem and should only be called once as it does not check for duplicate files */
static void create_blank_nodes_for_stress(struct file_t* _root_file, uint num_nodes)
{
    struct file_t* f1            = NULL;
    size_t         name_buf_size = 64;
    char*          name_buf      = calloc(name_buf_size, sizeof(char));
    if (name_buf == NULL)
    {
        printf("[%s]: Failed to create name buffer\n", __func__);
        return;
    }
    for (uint i = 0; i < num_nodes; i++)
    {
        snprintf(name_buf, name_buf_size, "file_0x%08X.txt", i);
        if (create_file(name_buf, &f1))
        {
            ANNOYING_PRINTF("[%s]: file created, appending...\n", __func__);
            if (!append_file(_root_file, f1))
            {
                ANNOYING_PRINTF("[%s]: appending failed, free file\n", __func__);
                free_files(f1);
            }
        }
    }
    FREE(name_buf);
}

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

    if (!create_file("/", &fs->root_file))
    {
        printf("Unable to create root file!\n");
        exit(1);
        return NULL;
    }

    fs->root_file->mode  = S_IFDIR | 0755;
    fs->root_file->nlink = 2;
    create_blank_nodes_for_stress(fs->root_file, 65536 / 256);
    double elapsed = 0.0;
    TIME_BLOCK_END(elapsed);
    printf("[%s]: Filesystem initialized in %fms\n", __func__, elapsed / 1000);
    return fs;
}

static void ramfs_destroy(void* _fs)
{
    struct filesystem_t* fs = _fs;
    free_files(fs->root_file);
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
// -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700L
int main(int argc, char* argv[])
{
    /* KDevelop buffers the output and will not display anything */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
#ifdef ENABLE_STATX
    printf("statx(2) support enabled!\n");
#endif
    fflush(stdout);

    int ret = fuse_main(argc, argv, &ramfs_operations, NULL);

    return ret;
}
