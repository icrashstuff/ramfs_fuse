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
#ifndef RAMFS_UTIL_H
#define RAMFS_UTIL_H

#include <sys/types.h>
#include <time.h>

/* Pure functions base their output solely on reading (or dereferencing) their inputs and never accessing global state, I think... - Ian */
#ifndef FUNC_PURE
#define FUNC_PURE __attribute__((pure))
#endif

/* Constant functions are pure functions with additional restrictions (ex. No pointer dereferencing) */
#ifndef FUNC_CONST
#define FUNC_CONST __attribute__((const))
#endif

extern int (*util_annoying_printf)(const char* fmt, ...);

#define ANNOYING_PRINTF(fmt, ...) util_annoying_printf(fmt, ##__VA_ARGS__)

#define DEREFERENCE_CRASH()    \
    do                         \
    {                          \
        int* __crash__ = NULL; \
        *__crash__     = 0;    \
    } while (0)

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

/**
 * This function is equivalent to GNU basename(3), in that it won't modify path
 */
FUNC_PURE const char* util_basename(const char* path);

/**
 * Gets the length of the directory part of a path for use in functions like strncmp(3)
 */
FUNC_PURE size_t util_dirname_len(const char* path, size_t path_len);

int util_annoying_prinf_null(const char* fmt, ...);

#endif // RAMFS_UTIL_H
