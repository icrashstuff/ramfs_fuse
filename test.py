#!/bin/env python3
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
#
# Formatted with `autopep8 --max-line-length  99`
import os
import sys
import time
import string
import random
import logging

logger = logging.getLogger(__name__)


def write_test_buf(fname: str, test_buf: bytes = random.randbytes(random.randrange(0, 64))):
    with open(fname, "wb") as fd:
        fd.write(test_buf)
        fd.flush()


def check_test_buf(fname: str, test_buf: bytes) -> bool:
    with open(fname, "rb") as fd:
        return (fd.read() == test_buf)


def remove_test_file(fname: str):
    try:
        os.remove(fname)
    except FileNotFoundError:
        pass


def test_writing_file_no_remove(fname: str, num_bytes: int):
    buf = random.randbytes(num_bytes)
    write_test_buf(fname, buf)
    if (check_test_buf(fname, buf)):
        return True
    else:
        return False


def test_writing_file(fname: str, num_bytes: int):
    ret = test_writing_file_no_remove(fname, num_bytes)
    os.remove(fname)
    return ret


# Testing that a file is not freed while there are open
def test_unlinking_while_open(fname: str, test_buf: bytes) -> bool:
    write_test_buf(fname, test_buf)
    with open(fname, "rb") as fd:
        os.remove(fname)

        fd.seek(0)
        cmpr_buf = fd.read()
        logger.debug(cmpr_buf)
        return (cmpr_buf == test_buf)


# This test is for verifying the truncate on w flag works properly
def test_writing_twice_to_file(fname: str, test_buf: bytes) -> bool:
    write_test_buf(fname, test_buf)
    with open(fname, "wb") as fd:
        pass
    if (check_test_buf(fname, b"")):
        os.remove(fname)
        return True
    else:
        os.remove(fname)
        return False


def test_symlink_create(fname: str, target: str) -> bool:
    remove_test_file(fname)
    try:
        os.symlink(target, fname)
        link_text = os.readlink(fname)
        ret = (target == link_text)
        remove_test_file(fname)
        return ret
    except Exception as e:
        remove_test_file(fname)
        raise e


def test_symlink_create_invalid(fname: str):
    write_test_buf(fname)
    try:
        os.symlink(fname, fname)
    except OSError as e:
        if (e.errno == 17):
            remove_test_file(fname)
            return True
    remove_test_file(fname)
    return False


def test_symlink_read_non_link(fname: str):
    write_test_buf(fname)
    try:
        os.readlink(fname)
    except OSError as e:
        if (e.errno == 22):
            return True
    return False


def test_rename(fname1: str, fname2: str, sizes: (int, int) = (64, 128)):
    buf1 = random.randbytes(sizes[0])
    write_test_buf(fname1, buf1)
    remove_test_file(fname2)
    os.rename(fname1, fname2)
    if (not check_test_buf(fname2, buf1)):
        logger.info("check_test_buf(fname2, buf1) failure")
        return False
    return True


def test_rename_overwrite(fname1: str, fname2: str, sizes: (int, int) = (64, 128)):
    buf1 = random.randbytes(sizes[0])
    buf2 = random.randbytes(sizes[1])
    write_test_buf(fname1, buf1)
    write_test_buf(fname2, buf2)
    os.rename(fname1, fname2)
    if (not check_test_buf(fname2, buf1)):
        logger.info("check_test_buf(fname2, buf1) failure")
        return False
    return True


# This shouldn't ever fail
def test_rename_self(fname1: str, num_bytes: int = 64):
    buf1 = random.randbytes(num_bytes)
    write_test_buf(fname1, buf1)
    os.rename(fname1, fname1)
    if (not check_test_buf(fname1, buf1)):
        logger.info("check_test_buf(fname2, buf1) failure")
        return False
    return True


def test_unlink_simple(fname1: str, num_bytes: int = 64):
    buf1 = random.randbytes(num_bytes)
    write_test_buf(fname1, buf1)
    os.remove(fname1)
    try:
        if (check_test_buf(fname1, buf1)):
            logger.info("check_test_buf(fname2, buf1) failure")
        return False
    except FileNotFoundError:
        return True


def test_hardlink_create(fname: str, target: str, num_bytes: int = 64) -> bool:
    remove_test_file(target)
    buf1 = random.randbytes(num_bytes)
    write_test_buf(fname, buf1)
    try:
        os.link(fname, target)
        ret = check_test_buf(fname, buf1)
        if (ret == 1):
            ret = check_test_buf(target, buf1)
        if (ret == 1):
            buf1 = random.randbytes(num_bytes)
            write_test_buf(fname, buf1)
            ret = check_test_buf(fname, buf1)
            if (ret == 1):
                ret = check_test_buf(target, buf1)
        remove_test_file(fname)
        remove_test_file(target)
        return ret
    except Exception as e:
        remove_test_file(fname)
        remove_test_file(target)
        raise e


def test_hardlink_create_invalid_exist(fname: str, target: str, num_bytes: int = 64) -> bool:
    write_test_buf(fname)
    write_test_buf(target)
    try:
        os.link(fname, target)
    except OSError as e:
        if (e.errno == 17):
            remove_test_file(fname)
            remove_test_file(target)
            return True
    remove_test_file(fname)
    remove_test_file(target)
    return False


def test_hardlink_create_invalid_nsrc(fname: str, target: str, num_bytes: int = 64) -> bool:
    remove_test_file(fname)
    remove_test_file(target)
    try:
        os.link(fname, target)
    except OSError as e:
        if (e.errno == 2):
            return True
    return False


def test_hardlink_delete(fname: str, target: str, del_sel: int, num_bytes: int = 64) -> bool:
    remove_test_file(target)
    buf1 = random.randbytes(num_bytes)
    write_test_buf(fname, buf1)
    try:
        os.link(fname, target)
        name_to_check = ""
        if (del_sel == 0):
            remove_test_file(fname)
            name_to_check = target
        else:
            remove_test_file(target)
            name_to_check = fname
        ret = check_test_buf(name_to_check, buf1)
        if (ret == 1):
            buf1 = random.randbytes(num_bytes)
            write_test_buf(name_to_check, buf1)
            ret = check_test_buf(name_to_check, buf1)
        remove_test_file(fname)
        remove_test_file(target)
        return ret
    except Exception as e:
        remove_test_file(fname)
        remove_test_file(target)
        raise e


def do_test(function, function_suffix, *args) -> bool:
    name = function.__name__
    if (function_suffix is str):
        name = "%s%s" % (name, function_suffix)
    try:
        ret = function(*args)
        if (ret):
            logger.debug("[%s]: passed!" % name)
        else:
            logger.info("[%s]: failed!" % name)
        return ret
    except Exception as e:
        if (e == KeyboardInterrupt):
            raise e
        logger.exception("Exception occured while running \"%s\"" % name)
        raise e
        return False


def do_test_list(test_list) -> [int, int]:
    results = [0, 0]
    for i in test_list:
        results[0] += 1
        if (len(i) > 1):
            results[1] += do_test(i[0], *i[1:])
        else:
            results[1] += do_test(i[0])
    return results


if __name__ == "__main__":
    if (len(sys.argv) < 2 or len(sys.argv) > 3):
        print("Usage: %s mountpoint [random_seed]" % sys.argv[0])
        exit(1)
    FORMAT = "[%(filename)s:%(lineno)s:%(funcName)s]: %(message)s"
    logging.basicConfig(format=FORMAT)
    logger.setLevel(logging.INFO)
    random_seed = random.randrange(0, int(pow(2, 32)))
    if (len(sys.argv) == 3):
        random_seed = int(sys.argv[2])
    logger.info("Random seed %d" % random_seed)
    seeded_random = random.Random(random_seed)

    fname_charset = string.ascii_letters + \
        string.digits + string.punctuation.replace("/", "")

    fnames1 = [os.path.join(sys.argv[1], "hello")]
    fnames1.append(os.path.join(sys.argv[1], "dir_0x0000/hello2"))
    fnames1.append(os.path.join(
        sys.argv[1], "dir_0x0000/dir_0x0001/dir_0x0002/hello3"))
    fnames2 = []

    for i in range(4):
        fname1 = os.path.join(sys.argv[1], "".join(seeded_random.choices(
            fname_charset, k=seeded_random.randrange(3, 16))))
        fnames1.append(fname1)
    for i in fnames1:
        fnames2.append(i + "_2")
    for i in [*fnames1, *fnames2]:
        if (os.path.exists(i)):
            logger.critical("File \"%s\" already exists" % i)
            sys.exit(1)

    test_list = []
    for _i in range(len(fnames1)):
        fname1 = fnames1[_i]
        fname2 = fnames2[_i]
        logger.info("fnames[%d]: (\"%s\", \"%s\")" % (_i, fname1, fname2))
        test_list.append([test_unlink_simple, None, fname1])
        test_list.append([test_unlinking_while_open, None,
                         fname1, seeded_random.randbytes(16)])
        test_list.append([test_writing_twice_to_file, None,
                         fname1, seeded_random.randbytes(16)])

        for i in range(8):
            num = seeded_random.randrange(int(pow(2, i)), int(pow(2, i+1)))
            target = "".join(seeded_random.choices(fname_charset, k=num))
            test_list.append([test_symlink_create, "_%d" %
                             num, fname1, target])

        test_list.append([test_symlink_read_non_link, None, fname1])
        test_list.append([test_symlink_create_invalid, None, fname1])

        test_list.append([test_hardlink_create, None, fname1, fname2])
        test_list.append([test_hardlink_create_invalid_exist, None, fname1, fname2])
        test_list.append([test_hardlink_create_invalid_nsrc, None, fname1, fname2])
        test_list.append([test_hardlink_delete, "_fname", fname1, fname2, 0])
        test_list.append([test_hardlink_delete, "_target", fname1, fname2, 1])

        test_list.append([test_rename, None, fname1, fname2])
        test_list.append([test_rename_overwrite, None, fname1, fname2])
        test_list.append([test_rename_self, None, fname1])

        for j in (test_writing_file_no_remove, test_writing_file):
            for k in range(24):
                num1 = int(pow(2, k-1))
                num2 = seeded_random.randrange(num1, int(pow(2, k)))
                test_list.append([j, "_%d" % num1, fname1, num1])
                test_list.append([j, "_%d" % num2, fname1, num2])

    try:
        os.mkdir(os.path.join(sys.argv[1], "dir_0x0000"))
    except FileExistsError:
        pass

    try:
        os.mkdir(os.path.join(sys.argv[1], "dir_0x0000/dir_0x0001"))
    except FileExistsError:
        pass

    try:
        os.mkdir(os.path.join(sys.argv[1], "dir_0x0000/dir_0x0001/dir_0x0002"))
    except FileExistsError:
        pass

    try:
        logger.info("Running test_list in input sequence")
        standard_seq_results = do_test_list(test_list)
        reversed(test_list)
        logger.info("Running test_list in reversed sequence")
        reversed_seq_results = do_test_list(test_list)
        seeded_random.shuffle(test_list)
        logger.info("Running test_list in randomized sequence 1")
        random_seq_results_1 = do_test_list(test_list)
        seeded_random.shuffle(test_list)
        logger.info("Running test_list in randomized sequence 2")
        random_seq_results_2 = do_test_list(test_list)

        logger.info("standard_seq_results: %d/%d" %
                    (standard_seq_results[1], standard_seq_results[0]))
        logger.info("reversed_seq_results: %d/%d" %
                    (reversed_seq_results[1], reversed_seq_results[0]))
        logger.info("random_seq_results_1: %d/%d" %
                    (random_seq_results_1[1], random_seq_results_1[0]))
        logger.info("random_seq_results_1: %d/%d" %
                    (random_seq_results_1[1], random_seq_results_1[0]))

        logger.info("Random seed %d" % random_seed)
    except Exception as e:
        for i in [*fnames1, *fnames2]:
            remove_test_file(i)
        raise e
    for i in [*fnames1, *fnames2]:
        remove_test_file(i)
