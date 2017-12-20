#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import unittest
import py2bpf.prog
import py2bpf.socket_filter


def compile_socket_filter(fn):
    p = py2bpf.prog.create_prog(
        py2bpf.prog.ProgType.SOCKET_FILTER,
        py2bpf.socket_filter.SkBuffContext,
        fn
    )
    p.close()


class BasicSmokeTest(unittest.TestCase):
    def test_simple_fn(self):
        def fn(ctx):
            return 0

        compile_socket_filter(fn)

    def test_simple_lambda(self):
        compile_socket_filter(lambda ctx: 0)


class StackSmokeTest(unittest.TestCase):
    def test_stack_variables(self):
        def fn(ctx):
            l = ctx.len
            return l

        compile_socket_filter(fn)


class MathSmokeTest(unittest.TestCase):
    def test_add(self):
        def fn(ctx):
            return ctx.len + ctx.protocol

        compile_socket_filter(fn)

    def test_subtract(self):
        def fn(ctx):
            return ctx.len - ctx.protocol

        compile_socket_filter(fn)

    def test_multiply(self):
        def fn(ctx):
            return ctx.len * ctx.protocol

        compile_socket_filter(fn)

    def test_floor_divide(self):
        def fn(ctx):
            return ctx.len // ctx.protocol

        compile_socket_filter(fn)

    def test_true_divide(self):
        def fn(ctx):
            return ctx.len / ctx.protocol

        compile_socket_filter(fn)

    def test_bit_and(self):
        def fn(ctx):
            return ctx.len & ctx.protocol

        compile_socket_filter(fn)

    def test_bit_or(self):
        def fn(ctx):
            return ctx.len | ctx.protocol

        compile_socket_filter(fn)

    def test_bit_rshift(self):
        def fn(ctx):
            return ctx.len >> ctx.protocol

        compile_socket_filter(fn)

    def test_bit_lshift(self):
        def fn(ctx):
            return ctx.len << ctx.protocol

        compile_socket_filter(fn)


if __name__ == '__main__':
    unittest.main()
