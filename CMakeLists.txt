# SPDX-License-Identifier: MIT
# 
# SPDX-FileCopyrightText: Copyright (c) 2024 Ian Hangartner <icrashstuff at outlook dot com>
# 
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

cmake_minimum_required(VERSION 3.10)

project(ramfs_fuse LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

include_directories(${FUSE3_INCLUDE_DIRS})

add_executable(ramfs_fuse main.c)

target_compile_definitions(ramfs_fuse PRIVATE _DEFAULT_SOURCE )
set(ENABLE_STATX OFF CACHE BOOL "Enables response to statx(2) (Requires libfuse to support statx)")
if(${ENABLE_STATX})
    target_compile_definitions(ramfs_fuse PRIVATE ENABLE_STATX _GNU_SOURCE)
endif()
target_link_libraries(ramfs_fuse ${FUSE3_LIBRARIES})
target_compile_options(ramfs_fuse PUBLIC ${FUSE3_CFLAGS_OTHER})

target_compile_options(ramfs_fuse PUBLIC -Wextra -Wall -Wno-unused-parameter)

install(TARGETS ramfs_fuse RUNTIME DESTINATION bin)
