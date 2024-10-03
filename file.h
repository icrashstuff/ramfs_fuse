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

#ifndef FILE_BUF_SIZE_ALIGN_HIGH
#define FILE_BUF_SIZE_ALIGN_HIGH 4096
#endif

/* This overrides FILE_BUF_SIZE_ALIGN_HIGH when req_size is less than FILE_BUF_SIZE_ALIGN_HIGH */
#ifndef FILE_BUF_SIZE_ALIGN_MID
#define FILE_BUF_SIZE_ALIGN_MID 256
#endif

/* This overrides FILE_BUF_SIZE_ALIGN_MID when req_size is less than FILE_BUF_SIZE_ALIGN_MID */
#ifndef FILE_BUF_SIZE_ALIGN_LOW
#define FILE_BUF_SIZE_ALIGN_LOW 64
#endif

/* When the buffer is below this percentage, shrink the buffer */
#ifndef FILE_BUF_SIZE_SHRINK_PERCENTAGE
#define FILE_BUF_SIZE_SHRINK_PERCENTAGE 50
#endif

#if FILE_BUF_SIZE_ALIGN_MID > FILE_BUF_SIZE_ALIGN_HIGH
#error "FILE_BUF_SIZE_ALIGN_MID cannot be greater than FILE_BUF_SIZE_ALIGN_HIGH"
#endif

#if FILE_BUF_SIZE_ALIGN_LOW > FILE_BUF_SIZE_ALIGN_MID
#error "FILE_BUF_SIZE_ALIGN_LOW cannot be greater than FILE_BUF_SIZE_ALIGN_MID"
#endif

struct file_t
{
    char*       basename;
    size_t      name_buf_size;

    struct file_t* parent;
    struct file_t* child;
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
int file_update_times(struct file_t* file, enum file_time_update_level_t level);

/**
 * Finds first file with name matching path limited to name_len if it were as long as name_len in first_file structure
 *
 * Returns 1 on success and 0 on failure
 */
int find_filen(const char* caller, const char* path, size_t name_len, struct file_t* first_file, struct file_t** found_file);

/**
 * Finds first file with name matching path in first_file structure
 *
 * Returns 1 on success and 0 on failure
 */
int find_file(const char* caller, const char* path, struct file_t* first_file, struct file_t** found_file);

/**
 * Appends new_file to the end of the current level list of first_file
 *
 * Returns 1 on success and 0 on failure
 */
int file_append_file(struct file_t* first_file, struct file_t* new_file);

/**
 * Appends new_file to the end of the child list of parent_file
 *
 * Returns 1 on success and 0 on failure
 */
int file_append_file_as_child(struct file_t* parent_file, struct file_t* new_file);

/**
 * Removes a file from the a file_t linked list
 *
 * Returns 1 on success and 0 on failure
 */
int file_remove_file(struct file_t* file);

/**
 * Frees a file, its children, and all following file_t->next entries
 *
 * Returns 1 on success and 0 on failure
 */
int file_free_files(struct file_t* first_file);

/**
 * Resizes the buffer to at least req_size and changes the file_size to req_size
 *
 * Returns 1 on success and 0 on failure
 */
int file_resize_buf(const char* caller, struct file_t* file, size_t req_size);

/**
 * Renames a file, this may involve reallocating file->name if the new name is longer
 *
 * Returns 1 on success and 0 on failure
 */
int file_rename(struct file_t* file, const char* new_name);

/**
 * Creates a file_t object and assigns the pointer at *file_ptr
 *
 * Returns 1 on success and 0 on failure
 */
int file_create(const char* name, struct file_t** file_ptr);

/**
 * Prints a tree(1)-like view of a file_t structure
 */
void file_print_tree(struct file_t* file, long int level);

/**
 * This is only meant to be used when initializing the filesystem
 *
 * Warning: This function is not thread safe as it relies on a static variable
 */
void file_create_blank_nodes_for_stress(struct file_t* _root_file, uint num_dirs, uint num_files);

#endif // RAMFS_FILE_H
