#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''This file evaluates as much of the instruction bytecode as possible by
loading globals into constants and applying constant folding.
'''

import collections
import ctypes
import py2bpf.datastructures
import py2bpf.funcs
import py2bpf.info
from py2bpf._translation import _vars, _dis_plus as dis


def _make_const(old, const_val):
    vi = _vars.VarInstruction(old, src_vars=[], dst_vars=old.dst_vars)
    vi.opcode = dis.OpCode.LOAD_CONST
    vi.opname = 'LOAD_CONST'
    vi.arg = -1
    vi.argval = const_val
    vi.argrepr = repr(const_val)
    return vi


def pin_globals_to_consts(src_fn, vis):
    ret = []
    for i in vis:
        if i.opcode == dis.OpCode.LOAD_GLOBAL:
            if i.argval in src_fn.__globals__:
                ret.append(_make_const(i, src_fn.__globals__[i.argval]))
            elif i.argval in __builtins__:
                ret.append(_make_const(i, __builtins__[i.argval]))
            else:
                raise NameError('name \'{}\' not defined'.format(i.argval))
        elif i.opcode == dis.OpCode.LOAD_DEREF:
            ret.append(_make_const(i, src_fn.__closure__[i.arg].cell_contents))
        else:
            ret.append(i)

    return ret


def reinterpret_const_strings(vis):
    ret = []
    for i in vis:
        if i.opcode == dis.OpCode.LOAD_CONST and isinstance(i.argval, str):
            val = i.argval.encode()
            val = list(val) + [0]
            val = (ctypes.c_char * len(val))(*val)
            ret.append(_make_const(i, val))
        else:
            ret.append(i)
    return ret


def fold_consts(vis):
    '''Fold constants within instructions. Leaves dead LOAD_CONSTs around'''
    class Const:
        def __init__(self, val):
            self.val = val

        def __repr__(self):
            return 'Const({})'.format(repr(self.val))

    class Multi:
        pass

    # We build var_map, which for every variable specifies whether it has
    # multiple sources, a single const source, or a single non-const
    # source. Yay for fake algebraic types!
    var_map = collections.defaultdict(list)
    for i in vis:
        v = Const(i.argval) if i.opcode == dis.OpCode.LOAD_CONST else None
        for dv in i.dst_vars:
            var_map[dv].append(v)
    var_map = {
        k: Multi() if len(v) > 1 and isinstance(v[0], Const) else v[0]
        for k, v in var_map.items()
    }

    # Now that we have the var map, we simply walk through looking for
    # opportunities to fold ops with all Const sources.
    ret = []
    for i in vis:
        srcs = [var_map[sv] for sv in i.src_vars]
        if len(srcs) == 0:
            ret.append(i)
            continue
        elif not all([isinstance(s, Const) for s in srcs]):
            ret.append(i)
            continue
        elif isinstance(srcs[0].val, py2bpf.datastructures.BpfMap):
            ret.append(i)
            continue

        srcs = [c.val for c in srcs]
        if i.opcode == dis.OpCode.BINARY_TRUE_DIVIDE:
            val = srcs[0] / srcs[1]
        elif i.opcode == dis.OpCode.BINARY_FLOOR_DIVIDE:
            val = srcs[0] // srcs[1]
        elif i.opcode == dis.OpCode.BINARY_MULTIPLY:
            val = srcs[0] * srcs[1]
        elif i.opcode == dis.OpCode.BINARY_ADD:
            val = srcs[0] + srcs[1]
        elif i.opcode == dis.OpCode.BINARY_SUBTRACT:
            val = srcs[0] - srcs[1]
        elif i.opcode == dis.OpCode.LOAD_ATTR:
            val = getattr(srcs[0], i.argval)
        elif i.opcode == dis.OpCode.BINARY_SUBSCR:
            val = srcs[0][srcs[1]]
        elif i.opcode == dis.OpCode.CALL_FUNCTION:
            # srcs = [fn] + [args] + [keyword, arg, ...]
            nargs, nkwargs = (i.arg & 0xff), (i.arg >> 8)
            fn = srcs[0]
            if (isinstance(fn, py2bpf.funcs.Func) or
                    isinstance(fn, py2bpf.funcs.PseudoFunc)):
                # This is a bpf function, so don't try to fold it
                ret.append(i)
                continue
            args = srcs[1:nargs + 1]
            kwargs = {
                srcs[nargs + 1 + i]: srcs[nargs + 2 + i] for i in range(nkwargs)
            }
            val = fn(*args, **kwargs)
        else:
            # Unable to fold this operation
            ret.append(i)
            continue

        ret.append(_make_const(i, val))
        # We can update the var_map to Const if it was not Multi, because
        # we know that we're the only source.
        for dv in i.dst_vars:
            if not isinstance(var_map[dv], Multi):
                var_map[dv] = Const(val)

    return ret


def remove_unread_consts(vis):
    '''Remove LOAD_CONST's that are unreferenced'''
    read_vars = set()
    for vi in vis:
        for sv in vi.src_vars:
            read_vars.add(sv)

    ret = []
    for vi in vis:
        if vi.opcode != dis.OpCode.LOAD_CONST or vi.dst_vars[0] in read_vars:
            ret.append(vi)

    return ret
