#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''This module exists to convert vanilla Vars into MemVars, which know
where they live in memory.
'''

import ctypes
import _ctypes
import py2bpf.exception
from py2bpf._translation import _types, _vars, _dis_plus as dis


class ArgVar:
    '''For variables that are arguments to the function'''
    def __init__(self, arg_num, var_type, offset):
        self.arg_num = arg_num
        self.var_type = var_type
        self.offset = offset

    def __str__(self):
        return 'ArgVar<{}>({}, {})'.format(
            self.var_type.__name__, self.arg_num, self.offset)


class FastVar:
    '''For named variables'''
    def __init__(self, name, var_type):
        self.name = name
        self.var_type = var_type

    def __str__(self):
        return 'FastVar<{}>({})'.format(self.var_type.__name__, self.name)


class ProbeVar:
    '''For variables that we must probe memory for'''
    def __init__(self):
        raise NotImplemented('No probes yet')


class ConstVar:
    '''For constants'''
    def __init__(self, val):
        self.var_type = type(val)
        self.val = val

    def __str__(self):
        return 'ConstVar<{}>({})'.format(self.var_type.__name__, self.val)


def convert_primitive_var_types(vis):
    def map_type(v):
        if issubclass(v.var_type, int):
            v.var_type = ctypes.c_uint64
        return v

    ret = []
    for i in vis:
        i.src_vars = [map_type(sv) for sv in i.src_vars]
        i.dst_vars = [map_type(dv) for dv in i.dst_vars]
        ret.append(i)

    return ret


def replace_load_consts(vis):
    const_map = {}
    seen_dst_vars = set()
    for i in vis:
        assert all([dv not in const_map for dv in i.dst_vars])
        if i.opcode == dis.OpCode.LOAD_CONST:
            assert i.dst_vars[0] not in seen_dst_vars, 'Multiple setters?'

            const_type = i.dst_vars[0].var_type
            const_val = i.argval
            if type(const_val) != const_type:
                const_val = const_type(const_val)
            const_map[i.dst_vars[0]] = ConstVar(const_val)

    ret = []
    for i in vis:
        if i.opcode != dis.OpCode.LOAD_CONST:
            i.src_vars = [const_map.get(sv, sv) for sv in i.src_vars]
            ret.append(i)
    return ret


def replace_arg_loads(vis, arg_types):
    ret = []
    arg_map = {}
    for i in vis:
        if i.opcode == dis.OpCode.LOAD_FAST and i.arg < len(arg_types):
            arg_map[i.dst_vars[0]] = ArgVar(i.arg, arg_types[i.arg], 0)
        elif i.opcode == dis.OpCode.STORE_FAST and i.arg < len(arg_types):
            raise py2bpf.exception.TranslationError(
                i.starts_line, 'Cannot overwrite argument {}'.format(i.argval))
        else:
            i.src_vars = [arg_map.get(sv, sv) for sv in i.src_vars]
            ret.append(i)
    return ret


def insert_fast_vars(vis):
    ret = []
    for i in vis:
        if i.opcode == dis.OpCode.LOAD_FAST:
            i.src_vars = [FastVar(i.argval, i.dst_vars[0].var_type)]
        elif i.opcode == dis.OpCode.STORE_FAST:
            st = i.src_vars[0].var_type
            if (not isinstance(i.src_vars[0], ConstVar) and
                    not issubclass(st, _ctypes._SimpleCData)):
                st = _types.make_ptr(st)
            i.dst_vars = [FastVar(i.argval, st)]
        ret.append(i)
    return ret


def replace_fast_loads(vis):
    load_map = {}
    ret = []
    for i in vis:
        if i.opcode == dis.OpCode.LOAD_FAST:
            load_map[i.dst_vars[0]] = i.src_vars[0]
        else:
            i.src_vars = [load_map.get(sv, sv) for sv in i.src_vars]
            ret.append(i)
    return ret


def replace_fast_stores(vis):
    store_map = {}
    for i in vis:
        if i.opcode == dis.OpCode.STORE_FAST:
            assert i.src_vars[0] not in store_map, 'Programmer error'
            store_map[i.src_vars[0]] = i.dst_vars[0]

    # Replace dst vars where we can
    ret = []
    for i in vis:
        if i.opcode != dis.OpCode.STORE_FAST:
            i.dst_vars = [store_map.get(dv, dv) for dv in i.dst_vars]
            ret.append(i)
        elif not isinstance(i.src_vars[0], _vars.Var):
            # Need to keep non-Var stores, like consts
            ret.append(i)
    return ret
