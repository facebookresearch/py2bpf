#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''This file does type checking and assignment'''

import _ctypes
import ctypes

import py2bpf.datastructures
import py2bpf.funcs
import py2bpf.exception
from py2bpf._translation import _vars, _dis_plus as dis


class Ptr(ctypes.c_voidp):
    pass


def make_ptr(var_type):
    name = 'Ptr_{}'.format(var_type.__name__)
    return type(name, (Ptr,), dict(var_type=var_type))


def set_dst_var_types(vis, arg_types):
    '''Return a map from var_number to type. This is where we clamp down on any
    inconsistency
    '''
    ret = []
    fast_types = {i: t for i, t in enumerate(arg_types)}
    fast_setters = {}
    var_types = {}
    var_setters = {}

    math_ops = set([
        dis.OpCode.BINARY_FLOOR_DIVIDE,
        dis.OpCode.BINARY_TRUE_DIVIDE,
        dis.OpCode.BINARY_MULTIPLY,
        dis.OpCode.BINARY_ADD,
        dis.OpCode.BINARY_SUBTRACT,
        dis.OpCode.BINARY_OR,
        dis.OpCode.BINARY_AND,
        dis.OpCode.BINARY_LSHIFT,
        dis.OpCode.BINARY_RSHIFT,
        dis.OpCode.INPLACE_FLOOR_DIVIDE,
        dis.OpCode.INPLACE_TRUE_DIVIDE,
        dis.OpCode.INPLACE_MULTIPLY,
        dis.OpCode.INPLACE_ADD,
        dis.OpCode.INPLACE_SUBTRACT,
        dis.OpCode.INPLACE_OR,
        dis.OpCode.INPLACE_AND,
    ])


    # Doesn't work for rotate-style instructions yet
    def update_var_type(var, var_type, ins):
        nonlocal var_types, var_setters
        if var in var_types and var_types[var] != var_type:
            old_type, old_line = var_types[var], var_setters[var].starts_line
            new_type, new_line = var_type, ins.starts_line
            raise py2bpf.exception.TranslationError(
                'Var set with new type {} at line {}: was {} at line {}'.format(
                    new_type, new_line, old_type, old_line))
        var_types[var] = var_type
        var_setters[var] = ins

    def update_single_dst(ins, var_type):
        # dst_vars may be empty if it's POP'ed (i.e. for side-effect
        # generating functions)
        if len(ins.dst_vars) == 0:
            return

        assert len(ins.dst_vars) == 1, 'Programmer error'
        update_var_type(ins.dst_vars[0], var_type, ins)

    def update_fast_type(ins, var_type):
        nonlocal fast_types, fast_setters
        arg = ins.arg
        if arg in fast_types and fast_types[arg] != var_type:
            old_type = fast_types[arg].__name__
            old_line = fast_setters[arg].starts_line
            new_type = var_type.__name__
            new_line = ins.starts_line
            raise py2bpf.exception.TranslationError(
                new_line, '{} set with new type {}, was {} at line {}'.format(
                    i.argval, new_type, old_type, old_line))
        fast_types[arg] = var_type
        fast_setters[arg] = ins

    def get_attr_type(i):
        obj_type = var_types[i.src_vars[0]]
        if issubclass(obj_type, Ptr):
            obj_type = obj_type.var_type

        # These overrides are used when we have a bpf field with type
        # uint32 but it's secretly manipulated into a pointer in the
        # verifier. Gross.
        dt_overrides = getattr(obj_type, '_dest_type_overrides_', {})
        if i.argval in dt_overrides:
            return dt_overrides[i.argval]

        for f, t in obj_type._fields_:
            if f == i.argval:
                if issubclass(t, _ctypes._SimpleCData):
                    return t
                else:
                    return make_ptr(t)

        raise py2bpf.exception.TranslationError(
            i.starts_line, 'No field {} within type {}'.format(
                i.argval, i.src_vars[0].var_type))

    def get_subscr_type(i):
        vt = var_types[i.src_vars[0]]
        if issubclass(vt, Ptr):
            vt = vt.var_type

        if issubclass(vt, ctypes.Array):
            return vt._type_
        elif issubclass(vt, py2bpf.datastructures.BpfMap):
            # Primitives by value, others by reference
            if issubclass(vt.VALUE_TYPE, _ctypes._SimpleCData):
                return vt.VALUE_TYPE
            else:
                return make_ptr(vt.VALUE_TYPE)
        else:
            raise py2bpf.exception.TranslationError(
                i.starts_line,
                'Binary subscription not supported for type {}'.format(
                    vt.__name__))

    for i in vis:
        if i.opcode == dis.OpCode.LOAD_GLOBAL:
            raise py2bpf.exception.TranslationError(
                i.starts_line, 'Cannot deduce type of LOAD_GLOBAL')
        elif i.opcode == dis.OpCode.LOAD_CONST:
            update_single_dst(i, type(i.argval))
        elif i.opcode == dis.OpCode.LOAD_FAST:
            if i.arg not in fast_types:
                raise py2bpf.exception.TranslationError(
                    i.starts_line, 'Unable to load unset variable {}'.format(
                        i.argval, i.starts_line))
            ft = fast_types[i.arg]
            if issubclass(ft, ctypes.Structure) or issubclass(ft, ctypes.Array):
                ft = make_ptr(ft)
            update_single_dst(i, ft)
        elif i.opcode == dis.OpCode.STORE_FAST:
            vt = var_types[i.src_vars[0]]
            if issubclass(vt, ctypes.Structure) or issubclass(vt, ctypes.Array):
                vt = make_ptr(vt)
            update_fast_type(i, vt)
        elif i.opcode in math_ops:
            update_single_dst(i, int)
        elif i.opcode == dis.OpCode.POP_JUMP_IF_FALSE:
            pass
        elif i.opcode == dis.OpCode.POP_JUMP_IF_TRUE:
            pass
        elif i.opcode == dis.OpCode.JUMP_FORWARD:
            pass
        elif i.opcode == dis.OpCode.RETURN_VALUE:
            pass
        elif i.opcode == dis.OpCode.STORE_ATTR:
            pass
        elif i.opcode == dis.OpCode.COMPARE_OP:
            update_single_dst(i, bool)
        elif i.opcode == dis.OpCode.LOAD_ATTR:
            update_single_dst(i, get_attr_type(i))
        elif i.opcode == dis.OpCode.BINARY_SUBSCR:
            update_single_dst(i, get_subscr_type(i))
        elif i.opcode == dis.OpCode.STORE_SUBSCR:
            pass
        elif i.opcode == dis.OpCode.DELETE_SUBSCR:
            pass
        elif i.opcode == dis.OpCode.CALL_FUNCTION:
            fn_i = var_setters[i.src_vars[0]]
            if fn_i.opcode != dis.OpCode.LOAD_CONST:
                raise TranslationError(
                    i.starts_line,
                    'Cannot invoke dynamically selected functions')
            fn = fn_i.argval
            if (not isinstance(fn, py2bpf.funcs.PseudoFunc) and
                    not isinstance(fn, py2bpf.funcs.Func)):
                raise TranslationError(
                    i.starts_line,
                    'Can only invoke py2bpf.funcs.Func or PseudoFunc')
            update_single_dst(i, fn.return_type)
        else:
            raise py2bpf.exception.TranslationError(
                i.starts_line,
                'Cannot deduce type for opcode: {}'.format(i.opname))

    ret = []
    for i in vis:
        i.dst_vars = [_vars.Var(dv.num, var_types[dv]) for dv in i.dst_vars]
        ret.append(i)

    return ret


def set_src_var_types(vis):
    var_types = {}
    for i in vis:
        for dv in i.dst_vars:
            var_types[dv] = dv.var_type
    ret = []
    for i in vis:
        i.src_vars = [_vars.Var(sv.num, var_types[sv]) for sv in i.src_vars]
        ret.append(i)
    return ret
