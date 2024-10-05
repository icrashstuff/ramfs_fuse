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

int inode_update_times(struct inode_t* inode, enum inode_time_update_level_t level)
{
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t))
        return 0;
    switch (level)
    {
    case INODE_TIME_LEVEL_CREATION:
        inode->btime = t;
        /* FALLTHRU */
    case INODE_TIME_LEVEL_MODIFY_CONTENTS:
        inode->mtime = t;
        inode->ctime = t; /* Contents being modified counts as a metadata change, I think */
        /* FALLTHRU */
    case INODE_TIME_LEVEL_ACCESS:
        inode->atime = t;
        break;
    case INODE_TIME_LEVEL_MODIFY_METADATA:
        inode->ctime = t;
        break;
    default:
        return 0;
    }
    return 1;
}

/**
 * Finds a lookup entry by recursing through the linked list and examining lookup_t->basename, sets found_lookup and returns true if name found
 */
static int _find_lookup_path_aware(size_t recur_level, const char* caller, const char* path_min, size_t path_min_len, const char* path, size_t path_len,
    struct lookup_t* first_lookup, struct lookup_t** found_lookup)
{
    if (first_lookup == NULL || path == NULL || found_lookup == NULL || path_len == 0)
        return 0;

#if 0
    for(size_t i = 0; i < recur_level*2; i++)
        putc(' ', stdout);
    printf("\"%s\" \t \"%s\"\n", first_lookup->basename, path_min);
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

    if (name_len == 0 && first_lookup->basename != NULL && strncmp(first_lookup->basename, path_min, path_min_len) == 0
        && first_lookup->basename[path_min_len] == '\0')
    {
        printf("[%s][%s]: found lookup \"%.*s\", level: %zu\n", caller, __func__, (int)path_len, path, recur_level);
        *found_lookup = first_lookup;
        return 1;
    }

    if ((name_len != 0 && strncmp(first_lookup->basename, &path_min[name_len_off], name_len) == 0))
    {
        if (first_lookup->child != NULL)
        {
            int ret = _find_lookup_path_aware(
                recur_level + 1, caller, &path_min[name_len + 1], path_min_len - (name_len + 1), path, path_len, first_lookup->child, found_lookup);
            if (ret != 0)
                return ret;
        }
    }
    else if (first_lookup->next != NULL)
    {
        int ret = _find_lookup_path_aware(recur_level, caller, path_min, path_min_len, path, path_len, first_lookup->next, found_lookup);
        if (ret != 0)
            return ret;
    }
    return 0;
}

int find_lookupn(const char* caller, const char* path, size_t name_len, struct lookup_t* first_lookup, struct lookup_t** found_lookup)
{
    TIME_BLOCK_START();
    if (path == NULL)
        return 0;
    if (path[0] == '/')
    {
        if (name_len == 1)
        {
            *found_lookup = first_lookup;
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
    if (first_lookup->child == NULL)
        return 0;
    first_lookup = first_lookup->child;

    int ret = _find_lookup_path_aware(0, caller, path, name_len, path, name_len, first_lookup, found_lookup);
    if (ret == 0)
        printf("[%s][%s]: did not find lookup \"%.*s\"\n", caller, __func__, (int)name_len, path);

    double elapsed = 0.0;
    TIME_BLOCK_END(elapsed);

    printf("[%s][%s]: Path: \"%.*s\", time: %fms\n", caller, __func__, (int)name_len, path, elapsed / 1000.0);
    return ret;
}

int find_lookup(const char* caller, const char* path, struct lookup_t* first_lookup, struct lookup_t** found_lookup)
{
    return find_lookupn(caller, path, strlen(path), first_lookup, found_lookup);
}

int find_inoden(const char* caller, const char* path, size_t name_len, struct lookup_t* first_lookup, struct inode_t** found_inode)
{
    struct lookup_t* l = NULL;

    int r = find_lookupn(caller, path, name_len, first_lookup, &l);

    if (l != NULL)
        *found_inode = l->inode_ptr;

    return r;
}
int find_inode(const char* caller, const char* path, struct lookup_t* first_lookup, struct inode_t** found_inode)
{
    struct lookup_t* l = NULL;

    int r = find_lookupn(caller, path, strlen(path), first_lookup, &l);

    if (l != NULL)
        *found_inode = l->inode_ptr;

    return r;
}

int lookup_append_lookup_as_next(struct lookup_t* first_lookup, struct lookup_t* new_lookup)
{
    if (first_lookup == NULL || new_lookup == NULL)
        return 0;
    struct lookup_t* cur_lookup = first_lookup;
    while (cur_lookup->next != NULL)
        cur_lookup = cur_lookup->next;
    cur_lookup->next = new_lookup;
    new_lookup->prev = cur_lookup;
    new_lookup->next = NULL;
    return 1;
}

int lookup_append_lookup_as_child(struct lookup_t* parent_lookup, struct lookup_t* new_lookup)
{
    if (parent_lookup == NULL || new_lookup == NULL)
        return 0;
    new_lookup->parent = parent_lookup;
    if (parent_lookup->child == NULL)
    {
        parent_lookup->child = new_lookup;
        return 1;
    }

    struct lookup_t* cur_lookup = parent_lookup->child;
    while (cur_lookup->next != NULL)
        cur_lookup = cur_lookup->next;
    cur_lookup->next = new_lookup;
    new_lookup->prev = cur_lookup;
    new_lookup->next = NULL;
    return 1;
}

int lookup_pluck_lookup(struct lookup_t* lookup)
{
    if (lookup == NULL)
        return 0;

    if (lookup->next != NULL)
        lookup->next->prev = lookup->prev;
    if (lookup->prev != NULL)
        lookup->prev->next = lookup->next;
    if (lookup->parent != NULL && lookup->parent->child == lookup)
        lookup->parent->child = lookup->next;

    lookup->parent = NULL;
    lookup->next   = NULL;
    lookup->prev   = NULL;

    return 1;
}

static int _lookup_free_lookups(struct lookup_t* first_lookup, int zero_nrefs)
{
    if (first_lookup == NULL)
        return 0;
    struct lookup_t* next_lookup  = first_lookup->next;
    struct lookup_t* child_lookup = first_lookup->child;
    FREE(first_lookup->basename);
    if (zero_nrefs)
    {
        first_lookup->inode_ptr->nlink--;
        first_lookup->inode_ptr->nrefs = 0;
    }
    inode_free_inode(first_lookup->inode_ptr);
    FREE(first_lookup);
    if (child_lookup != NULL)
        _lookup_free_lookups(child_lookup, zero_nrefs);
    if (next_lookup != NULL)
        _lookup_free_lookups(next_lookup, zero_nrefs);
    return 1;
}

int lookup_free_lookups(struct lookup_t* first_lookup) { return _lookup_free_lookups(first_lookup, 0); }

int lookup_free_lookups_no_refs(struct lookup_t* first_lookup) { return _lookup_free_lookups(first_lookup, 1); }

int lookup_pluck_and_free_lookup(struct lookup_t* lookup)
{
    if (lookup == NULL)
        return 0;
    if (!lookup_pluck_lookup(lookup))
        return 0;
    lookup->inode_ptr->nlink--;
    if (!lookup_free_lookups(lookup))
        return 0;
    return 1;
}

static size_t next_inode_num = 0;

int inode_free_inode(struct inode_t* inode)
{
    if (inode == NULL)
        return 0;
    if (inode->nrefs > 0)
        return 1;
    if (inode->nlink > 1)
        return 1;
    if (inode->nlink > 0 && !(inode->mode & S_IFDIR))
        return 1;
    ANNOYING_PRINTF("[%s]: Freeing inode %09zu/%zu\n", __func__, inode->inode_num, next_inode_num - 1);
    FREE(inode->buf);
    FREE(inode);
    return 1;
}

int inode_resize_buf(const char* caller, struct inode_t* inode, size_t req_size)
{
    if (inode == NULL)
        return 0;
    size_t size = 0;
    if (req_size != 0)
    {
        if (req_size < INODE_BUF_SIZE_ALIGN_MID)
            size = ((req_size / INODE_BUF_SIZE_ALIGN_LOW) + 1) * INODE_BUF_SIZE_ALIGN_LOW;
        else if (req_size < INODE_BUF_SIZE_ALIGN_HIGH)
            size = ((req_size / INODE_BUF_SIZE_ALIGN_MID) + 1) * INODE_BUF_SIZE_ALIGN_MID;
        else
            size = ((req_size / INODE_BUF_SIZE_ALIGN_HIGH) + 1) * INODE_BUF_SIZE_ALIGN_HIGH;
    }
    ANNOYING_PRINTF(
        "[%s][%s]: Resize %ld size(buf): %zu(%zu)->%zu(%zu)\n", caller, __func__, inode->inode_num, inode->file_size, inode->buf_size, req_size, size);

    if (size == 0)
    {
        FREE(inode->buf);
        inode->buf_size  = 0;
        inode->file_size = 0;
        return 1;
    }

    if (inode->buf_size < size || size < (inode->buf_size * INODE_BUF_SIZE_SHRINK_PERCENTAGE / 100))
    {
        char* new_ptr;
        if (inode->buf != NULL)
            new_ptr = realloc(inode->buf, size);
        else
            new_ptr = calloc(size, sizeof(char));
        if (new_ptr == NULL)
            return 0;
        inode->buf_size = size;
        inode->buf      = new_ptr;
        if (inode->file_size < size)
        {
            size_t diff = size - inode->file_size;
            memset(&inode->buf[inode->file_size], 0, diff);
        }
    }

    inode->file_size = req_size;
    return 1;
}

int lookup_rename(struct lookup_t* lookup, const char* _new_name)
{
    if (lookup == NULL)
        return 0;
    const char* new_basename = util_basename(_new_name);
    size_t      old_name_len = 0;
    size_t      new_name_len = strlen(new_basename) + 1;

    if (lookup->basename != NULL)
        old_name_len = lookup->name_buf_size;

    if (new_name_len == 0)
    {
        FREE(lookup->basename);
        lookup->name_buf_size = 0;
        return 1;
    }
    else if (old_name_len < new_name_len)
    {
        char* new_name_buf = calloc(new_name_len, sizeof(char));
        char* old_name_buf = lookup->basename;
        if (new_name_buf == NULL)
            return 0;
        memcpy(new_name_buf, new_basename, new_name_len);
        lookup->basename = new_name_buf;
        FREE(old_name_buf);
        return 1;
    }
    else if (new_name_len < old_name_len)
    {
        memcpy(lookup->basename, new_basename, new_name_len);
        return 1;
    }

    return 0;
}

int lookup_create(const char* name, struct lookup_t** lookup_ptr)
{
    if (lookup_ptr == NULL)
        return 0;
    struct lookup_t* lookup = calloc(1, sizeof(struct lookup_t));
    struct inode_t*  inode  = calloc(1, sizeof(struct inode_t));
    if (inode == NULL || lookup == NULL)
    {
        FREE(lookup);
        FREE(inode);
        return 0;
    }
    if (!lookup_rename(lookup, name))
        return 0;
    inode_resize_buf(__func__, inode, 0);
    inode_update_times(inode, INODE_TIME_LEVEL_CREATION);
    inode->uid       = getuid();
    inode->gid       = getuid();
    inode->mode      = S_IFREG | 0644;
    inode->nlink     = 1;
    inode->inode_num = next_inode_num++;

    lookup->inode_ptr = inode;
    *lookup_ptr       = lookup;

    return 1;
}

int lookup_clone_lookup(const char* name, struct lookup_t* src_lookup, struct lookup_t** lookup_ptr)
{
    if (lookup_ptr == NULL || src_lookup == NULL || src_lookup->inode_ptr == NULL)
        return 0;
    struct lookup_t* lookup = calloc(1, sizeof(struct lookup_t));
    if (lookup == NULL)
    {
        FREE(lookup);
        return 0;
    }
    if (!lookup_rename(lookup, name))
        return 0;

    /* Incrementing nlink counts as modifying metadata */
    inode_update_times(src_lookup->inode_ptr, INODE_TIME_LEVEL_MODIFY_METADATA);
    src_lookup->inode_ptr->nlink++;

    lookup->inode_ptr = src_lookup->inode_ptr;
    *lookup_ptr       = lookup;

    return 1;
}

void lookup_print_tree(struct lookup_t* lookup, long int level)
{
    if (lookup == NULL)
        return;
    for (int i = 0; i < level; i++)
    {
        if (i % 4 == 0)
            putc('|', stdout);
        else
            putc(' ', stdout);
    }
    printf("+ \"%s\"\n", lookup->basename);

    lookup_print_tree(lookup->child, level + 4);
    lookup_print_tree(lookup->next, level);
}

void lookup_create_blank_nodes_for_stress(struct lookup_t* _root_lookup, uint num_dirs, uint num_files)
{
    struct inode_t*  f1            = NULL;
    struct lookup_t* l1            = NULL;
    struct lookup_t* dir           = _root_lookup;
    int              name_buf_size = 128;
    char*            fname_buf     = calloc(name_buf_size, sizeof(char));

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
            if (lookup_create(fname_buf, &l1))
            {
                ANNOYING_PRINTF("[%s]: file created, appending...\n", __func__);
                if (!lookup_append_lookup_as_child(dir, l1))
                {
                    ANNOYING_PRINTF("[%s]: appending failed, freeing file...\n", __func__);
                    lookup_free_lookups(l1);
                }
            }
        }

        sn_ret = snprintf(fname_buf, name_buf_size, "dir_0x%04X", counter_dir++);
        if (sn_ret > name_buf_size)
            continue;
        if (lookup_create(fname_buf, &l1))
        {
            f1 = l1->inode_ptr;
            ANNOYING_PRINTF("[%s]: directory created, appending...\n", __func__);
            f1->mode &= ~S_IFMT;
            f1->mode |= S_IFDIR;
            f1->nlink = 2;
            if (!lookup_append_lookup_as_child(dir, l1))
            {
                ANNOYING_PRINTF("[%s]: appending failed, freeing directory...\n", __func__);
                lookup_free_lookups(l1);
            }
            else
                dir = l1;
        }
    }
    FREE(fname_buf);
}
