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
#include "file.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int file_update_times(struct file_t* file, enum file_time_update_level_t level)
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

/**
 * Finds a file by recursing through the linked list and examining file_t->basename, sets found_file and returns true if name found
 */
static int _find_file_path_aware(size_t recur_level, const char* caller, const char* path_min, size_t path_min_len, const char* path, size_t path_len,
    struct file_t* first_file, struct file_t** found_file)
{
    if (first_file == NULL || path == NULL || found_file == NULL || path_len == 0)
        return 0;

#if 0
    for(size_t i = 0; i < recur_level*2; i++)
        putc(' ', stdout);
    printf("\"%s\" \t \"%s\"\n", first_file->name, path_min);
#endif

    size_t name_len     = 0;
    size_t name_len_off = 0;
    for (size_t i = 0; i < path_min_len; i++)
    {
        if (path_min[i] == '/')
        {
            name_len = i;
            i        = path_min_len;
        }
    }

    if (name_len == 0 && first_file->basename != NULL && strncmp(first_file->basename, path_min, path_min_len) == 0
        && first_file->basename[path_min_len] == '\0')
    {
        printf("[%s][%s]: %zu found file \"%.*s\", level: %zu\n", caller, __func__, name_len, (int)path_len, path, recur_level);
        *found_file = first_file;
        return 1;
    }

    if ((name_len != 0 && strncmp(first_file->basename, &path_min[name_len_off], name_len) == 0))
    {
        if (first_file->child != NULL)
        {
            int ret = _find_file_path_aware(
                recur_level + 1, caller, &path_min[name_len + 1], path_min_len - (name_len + 1), path, path_len, first_file->child, found_file);
            if (ret != 0)
                return ret;
        }
    }
    else if (first_file->next != NULL)
    {
        int ret = _find_file_path_aware(recur_level, caller, path_min, path_min_len, path, path_len, first_file->next, found_file);
        if (ret != 0)
            return ret;
    }
    return 0;
}

int find_filen(const char* caller, const char* path, size_t name_len, struct file_t* first_file, struct file_t** found_file)
{
    TIME_BLOCK_START();
    if (path == NULL)
        return 0;
    if (path[0] == '/')
    {
        if (name_len == 1)
        {
            *found_file = first_file;
            return 1;
        }
        else if (name_len > 1)
        {
            path = &path[1];
            name_len--;
        }
    }
    if (name_len > 0 && path[name_len - 1] == '/')
        name_len--;
    if (first_file->child == NULL)
        return 0;
    first_file = first_file->child;

    int ret = _find_file_path_aware(0, caller, path, name_len, path, name_len, first_file, found_file);
    if (ret == 0)
        printf("[%s][%s]: did not find file \"%.*s\"\n", caller, __func__, (int)name_len, path);

    double elapsed = 0.0;
    TIME_BLOCK_END(elapsed);

    printf("[%s][%s]: Path: \"%.*s\", time: %fms\n", caller, __func__, (int)name_len, path, elapsed / 1000.0);
    return ret;
}

int find_file(const char* caller, const char* path, struct file_t* first_file, struct file_t** found_file)
{
    return find_filen(caller, path, strlen(path), first_file, found_file);
}

int file_append_file(struct file_t* first_file, struct file_t* new_file)
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

int file_append_file_as_child(struct file_t* parent_file, struct file_t* new_file)
{
    if (parent_file == NULL || new_file == NULL)
        return 0;
    new_file->parent = parent_file;
    if (parent_file->child == NULL)
    {
        parent_file->child = new_file;
        return 1;
    }

    struct file_t* cur_file = parent_file->child;
    while (cur_file->next != NULL)
        cur_file = cur_file->next;
    cur_file->next = new_file;
    new_file->prev = cur_file;
    new_file->next = NULL;
    return 1;
}

int file_remove_file(struct file_t* file)
{
    if (file == NULL)
        return 0;
    if (file->child != NULL)
        return 0;

    if (file->next != NULL)
        file->next->prev = file->prev;
    if (file->prev != NULL)
        file->prev->next = file->next;
    if (file->parent != NULL && file->parent->child == file)
        file->parent->child = file->next;

    file->parent = NULL;
    file->next   = NULL;
    file->prev   = NULL;

    return 1;
}

int file_free_files(struct file_t* first_file)
{
    if (first_file == NULL)
        return 0;
    struct file_t* next_file  = first_file->next;
    struct file_t* child_file = first_file->child;
    FREE(first_file->basename);
    FREE(first_file->buf);
    FREE(first_file);
    if (child_file != NULL)
        file_free_files(next_file);
    if (next_file != NULL)
        file_free_files(next_file);
    return 1;
}

int file_resize_buf(const char* caller, struct file_t* file, size_t req_size)
{
    if (file == NULL)
        return 0;
    size_t size = 0;
    if (req_size != 0)
    {
        if (req_size < FILE_BUF_SIZE_ALIGN_MID)
            size = ((req_size / FILE_BUF_SIZE_ALIGN_LOW) + 1) * FILE_BUF_SIZE_ALIGN_LOW;
        else if (req_size < FILE_BUF_SIZE_ALIGN_HIGH)
            size = ((req_size / FILE_BUF_SIZE_ALIGN_MID) + 1) * FILE_BUF_SIZE_ALIGN_MID;
        else
            size = ((req_size / FILE_BUF_SIZE_ALIGN_HIGH) + 1) * FILE_BUF_SIZE_ALIGN_HIGH;
    }
    printf("[%s][%s]: Resize \"%s\" size(buf): %zu(%zu)->%zu(%zu)\n", caller, __func__, file->basename, file->file_size, file->buf_size, req_size, size);

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

int file_rename(struct file_t* file, const char* _new_name)
{
    if (file == NULL)
        return 0;
    const char* new_basename = util_basename(_new_name);
    size_t      old_name_len = 0;
    size_t      new_name_len = strlen(new_basename) + 1;

    if (file->basename != NULL)
        old_name_len = file->name_buf_size;

    if (new_name_len == 0)
    {
        FREE(file->basename);
        file->name_buf_size = 0;
        return 1;
    }
    else if (old_name_len < new_name_len)
    {
        char* new_name_buf = calloc(new_name_len, sizeof(char));
        char* old_name_buf = file->basename;
        if (new_name_buf == NULL)
            return 0;
        memcpy(new_name_buf, new_basename, new_name_len);
        file->basename = new_name_buf;
        FREE(old_name_buf);
        return 1;
    }
    else if (new_name_len < old_name_len)
    {
        memcpy(file->basename, new_basename, new_name_len);
        return 1;
    }

    return 0;
}

int file_create(const char* name, struct file_t** file_ptr)
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
    file->mode  = S_IFREG | 0644;
    file->nlink = 1;

    *file_ptr = file;
    return 1;
}

void file_print_tree(struct file_t* file, long int level)
{
    if (file == NULL)
        return;
    for (int i = 0; i < level; i++)
    {
        if (i % 4 == 0)
            putc('|', stdout);
        else
            putc(' ', stdout);
    }
    printf("+ \"%s\"\n", file->basename);

    file_print_tree(file->child, level + 4);
    file_print_tree(file->next, level);
}

void file_create_blank_nodes_for_stress(struct file_t* _root_file, uint num_dirs, uint num_files)
{
    struct file_t* f1            = NULL;
    struct file_t* dir           = _root_file;
    int            name_buf_size = 128;
    char*          fname_buf     = calloc(name_buf_size, sizeof(char));

    if (fname_buf == NULL)
    {
        printf("[%s]: Failed to create name buffer\n", __func__);
        return;
    }

    static uint counter_dir  = 0;
    static uint counter_file = 0;

    for (uint j = 0; j < num_dirs; j++)
    {
        int sn_ret = 0;
        for (uint k = 0; k < num_files; k++)
        {
            sn_ret = snprintf(fname_buf, name_buf_size, "file_0x%04X.txt", counter_file++);
            if (sn_ret > name_buf_size)
                continue;
            if (file_create(fname_buf, &f1))
            {
                ANNOYING_PRINTF("[%s]: file created, appending...\n", __func__);
                if (!file_append_file_as_child(dir, f1))
                {
                    ANNOYING_PRINTF("[%s]: appending failed, freeing file...\n", __func__);
                    file_free_files(f1);
                }
            }
        }

        sn_ret = snprintf(fname_buf, name_buf_size, "dir_0x%04X", counter_dir++);
        if (sn_ret > name_buf_size)
            continue;
        if (file_create(fname_buf, &f1))
        {
            ANNOYING_PRINTF("[%s]: directory created, appending...\n", __func__);
            f1->mode &= ~S_IFMT;
            f1->mode |= S_IFDIR;
            f1->nlink = 2;
            if (!file_append_file_as_child(dir, f1))
            {
                ANNOYING_PRINTF("[%s]: appending failed, freeing directory...\n", __func__);
                file_free_files(f1);
            }
            else
                dir = f1;
        }
    }
    FREE(fname_buf);
}
