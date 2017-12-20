#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''This module exists to create stack allocations for variables'''

import ctypes

from py2bpf._translation import _datastructures, _mem, _vars


class StackVar:
    '''For variables located on the stack (i.e. non-fast vars)'''
    def __init__(self, var_type, offset):
        self.var_type = var_type
        self.offset = offset

    def __str__(self):
        return 'StackVar<{}>(offset={})'.format(
            self.var_type.__name__, self.offset)


class Stack:
    '''Simple bump allocator for the stack'''
    def __init__(self):
        self.neg_stack_off = 0

    def alloc(self, var_type):
        # Treat these as pointers for stack storage purposes
        if issubclass(var_type, _datastructures.FileDescriptorDatastructure):
            var_type = ctypes.c_voidp

        # Round up to nearest multiple of alignment. This works
        # because alignment is always a power of 2
        al = ctypes.alignment(var_type)
        self.neg_stack_off += ctypes.sizeof(var_type)
        self.neg_stack_off += (al - 1)
        self.neg_stack_off &= ~(al - 1)
        return StackVar(var_type, -self.neg_stack_off)


def set_stack_allocations(vis):
    '''Convert _vars.Var to StackVar. Allocate to the stack using a simple bump
    allocator. This is less efficient, but we don't need to pay attention
    to variable lifetime, which is rad.
    '''
    ret = []
    stack = Stack()
    trans_map = {}
    fast_map = {}
    for i in vis:
        dst_vars = []
        for dv in i.dst_vars:
            if isinstance(dv, _vars.Var):
                if dv not in trans_map:
                    trans_map[dv] = stack.alloc(dv.var_type)
                dst_vars.append(trans_map[dv])
            elif isinstance(dv, _mem.FastVar):
                if dv.name not in fast_map:
                    fast_map[dv.name] = stack.alloc(dv.var_type)
                dst_vars.append(fast_map[dv.name])
            else:
                dst_vars.append(dv)
        src_vars = []
        for sv in i.src_vars:
            if isinstance(sv, _vars.Var):
                src_vars.append(trans_map[sv])
            elif isinstance(sv, _mem.FastVar):
                src_vars.append(fast_map[sv.name])
            else:
                src_vars.append(sv)
        i.dst_vars = dst_vars
        i.src_vars = src_vars
        ret.append(i)

    return ret, stack
