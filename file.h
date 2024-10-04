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
#ifndef RAMFS_FILE_H
#define RAMFS_FILE_H

#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifndef INODE_BUF_SIZE_ALIGN_HIGH
#define INODE_BUF_SIZE_ALIGN_HIGH 4096
#endif

/* This overrides INODE_BUF_SIZE_ALIGN_HIGH when req_size is less than INODE_BUF_SIZE_ALIGN_HIGH */
#ifndef INODE_BUF_SIZE_ALIGN_MID
#define INODE_BUF_SIZE_ALIGN_MID 256
#endif

/* This overrides INODE_BUF_SIZE_ALIGN_MID when req_size is less than INODE_BUF_SIZE_ALIGN_MID */
#ifndef INODE_BUF_SIZE_ALIGN_LOW
#define INODE_BUF_SIZE_ALIGN_LOW 64
#endif

/* When the buffer is below this percentage, shrink the buffer */
#ifndef INODE_BUF_SIZE_SHRINK_PERCENTAGE
#define INODE_BUF_SIZE_SHRINK_PERCENTAGE 50
#endif

#if INODE_BUF_SIZE_ALIGN_MID > INODE_BUF_SIZE_ALIGN_HIGH
#error "INODE_BUF_SIZE_ALIGN_MID cannot be greater than INODE_BUF_SIZE_ALIGN_HIGH"
#endif

#if INODE_BUF_SIZE_ALIGN_LOW > INODE_BUF_SIZE_ALIGN_MID
#error "INODE_BUF_SIZE_ALIGN_LOW cannot be greater than INODE_BUF_SIZE_ALIGN_MID"
#endif

struct inode_t
{
    size_t inode_num;

    size_t buf_size;
    size_t file_size;
    char*  buf;

    /**
     * Access time
     * Because this is a ramfs we will update this every time
     * the contents of buf are modified, read, or created
     *
     * see strictatime and relatime fs mount options for future ideas
     */
    struct timespec atime;
    /** Metadata Modification time (also includes non-zero calls to write) */
    struct timespec ctime;
    /** Content Modification time */
    struct timespec mtime;
    /** inode_t creation time (should not be changed) */
    struct timespec btime;

    uid_t uid;
    gid_t gid;

    mode_t mode;
    /**
     * Number of hard links to inode, in the case of directories there is the . directory which increases the value to 1
     * If nlink and refs both hit 0, then delete (this will be important when and if hardlinks are implemented)
     */
    nlink_t nlink;
    /**
     * Number of unreleased open() calls to the inode
     * If nlink and refs both hit 0, then the inode can be deleted (this will be important when and if hardlinks are implemented)
     */
    size_t nrefs;
};

struct lookup_t
{
    char*  basename;
    size_t name_buf_size;

    struct lookup_t* parent;
    struct lookup_t* child;
    struct lookup_t* prev;
    struct lookup_t* next;

    /** inode_ptr must ALWAYS be a valid pointer */
    struct inode_t* inode_ptr;
};

struct filesystem_t
{
    struct lookup_t* root_lookup;
};

/**
 * Values that control which time fields will be updated by inode_update_times
 */
enum inode_time_update_level_t
{
    INODE_TIME_LEVEL_ACCESS          = 0,
    INODE_TIME_LEVEL_MODIFY_METADATA = 1,
    INODE_TIME_LEVEL_MODIFY_CONTENTS = 2,
    INODE_TIME_LEVEL_CREATION        = 3,
};

/**
 * Helper function to update appropriate inode times
 *
 * Returns 1 on success and 0 on failure
 */
int inode_update_times(struct inode_t* inode, enum inode_time_update_level_t level);

/**
 * Finds first lookup with name matching path limited to name_len if it were as long as name_len in first_lookup structure
 *
 * Returns 1 on success and 0 on failure
 */
int find_lookupn(const char* caller, const char* path, size_t name_len, struct lookup_t* first_lookup, struct lookup_t** found_lookup);

/**
 * Finds first lookup with name matching path in first_lookup structure
 *
 * Returns 1 on success and 0 on failure
 */
int find_lookup(const char* caller, const char* path, struct lookup_t* first_lookup, struct lookup_t** found_lookup);

/**
 * Appends new_lookup to the end of the current level list of first_lookup
 *
 * Returns 1 on success and 0 on failure
 */
int lookup_append_lookup_as_next(struct lookup_t* first_lookup, struct lookup_t* new_lookup);

/**
 * Appends new_lookup to the end of the child list of parent_file
 *
 * Returns 1 on success and 0 on failure
 */
int lookup_append_lookup_as_child(struct lookup_t* parent_lookup, struct lookup_t* new_lookup);

/**
 * Removes a lookup from the a lookup_t linked list
 *
 * Returns 1 on success and 0 on failure
 */
int lookup_pluck_lookup(struct lookup_t* lookup);

/**
 * Frees a lookup, its children, and all following lookup_t->next entries
 *
 * Also frees the underlying inode
 *
 * Returns 1 on success and 0 on failure
 */
int lookup_free_lookups(struct lookup_t* first_lookup);

/**
 * Resizes the buffer to at least req_size and changes the file_size to req_size
 *
 * Returns 1 on success and 0 on failure
 */
int inode_resize_buf(const char* caller, struct inode_t* inode, size_t req_size);

/**
 * Renames a lookup, this may involve reallocating lookup_t->name if the new name is longer
 *
 * Returns 1 on success and 0 on failure
 */
int lookup_rename(struct lookup_t* lookup, const char* new_name);

/**
 * Creates a lookup_t object and assigns the pointer at *lookup_ptr
 *
 * Returns 1 on success and 0 on failure
 */
int lookup_create(const char* name, struct lookup_t** lookup_ptr);

/**
 * Prints a tree(1)-like view of a lookup_t structure
 */
void lookup_print_tree(struct lookup_t* lookup, long int level);

/**
 * This is only meant to be used when initializing the filesystem
 *
 * Warning: This function is not thread safe as it relies on a static variable
 */
void lookup_create_blank_nodes_for_stress(struct lookup_t* _root_lookup, uint num_dirs, uint num_files);

#endif // RAMFS_FILE_H
