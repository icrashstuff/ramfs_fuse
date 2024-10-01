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
#include "util.h"
#include <string.h>

const char* util_basename(const char* path)
{
    if (path == NULL)
        return ".";
    size_t len       = strlen(path);
    size_t start_pos = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (path[i] == '/')
            start_pos = i + 1;
    }

    if (start_pos < len)
        return &path[start_pos];
    else
        return ".";
}

size_t util_dirname_len(const char* path, size_t path_len)
{
    size_t dir_len = 0;
    for (size_t i = 0; i < path_len; i++)
    {
        if (path[i] == '/')
            dir_len = i;
    }
    if (dir_len == 0 && path_len > 1 && path[dir_len] == '/')
        dir_len++;
    return dir_len;
}
