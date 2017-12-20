#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''Functions for translating from python functions to bpf bytecode'''

import sys

from py2bpf._translation import (
    _folding, _labels, _mem, _stack, _types, _vars, _dis_plus as dis)


def _ensure_translatable_ops(instructions):
    '''Ensure that all of the opcodes are things that we're familiar with so
    that we have some protection from an unknown opcode causing a confusing
    failure somewhere deep inside of our guts.
    '''
    ok_opcodes = set([
        dis.OpCode.BINARY_ADD,
        dis.OpCode.BINARY_AND,
        dis.OpCode.BINARY_FLOOR_DIVIDE,
        dis.OpCode.BINARY_LSHIFT,
        dis.OpCode.BINARY_MULTIPLY,
        dis.OpCode.BINARY_OR,
        dis.OpCode.BINARY_RSHIFT,
        dis.OpCode.BINARY_SUBSCR,
        dis.OpCode.BINARY_SUBTRACT,
        dis.OpCode.BINARY_TRUE_DIVIDE,
        dis.OpCode.CALL_FUNCTION,
        dis.OpCode.COMPARE_OP,
        dis.OpCode.DELETE_SUBSCR,
        dis.OpCode.DUP_TOP,
        dis.OpCode.DUP_TOP_TWO,
        dis.OpCode.INPLACE_ADD,
        dis.OpCode.JUMP_FORWARD,
        dis.OpCode.LOAD_ATTR,
        dis.OpCode.LOAD_CONST,
        dis.OpCode.LOAD_DEREF,
        dis.OpCode.LOAD_FAST,
        dis.OpCode.LOAD_GLOBAL,
        dis.OpCode.POP_JUMP_IF_FALSE,
        dis.OpCode.POP_JUMP_IF_TRUE,
        dis.OpCode.POP_TOP,
        dis.OpCode.RETURN_VALUE,
        dis.OpCode.ROT_THREE,
        dis.OpCode.ROT_TWO,
        dis.OpCode.STORE_ATTR,
        dis.OpCode.STORE_FAST,
        dis.OpCode.STORE_SUBSCR,
    ])
    bad_ops = set()
    for i in instructions:
        if i.opcode not in ok_opcodes:
            print('Got untranslatable instruction {} at line {}'.format(
                i.opname, i.starts_line), file=sys.stderr)
            bad_ops.add(i.opname)

    if len(bad_ops) > 0:
        raise ValueError('Got untranslatable opcodes: {}'.format(
            ', '.join(bad_ops)))


def convert_to_register_ops(fn, ctx_type, verbose=False):
    '''Convert stack-based vm bytecode to register/stack based
    pseudo-bytecode
    '''
    arg_types = [ctx_type]

    def verbose_fn(*args, **kwargs):
        nonlocal verbose
        if verbose:
            print(*args, **kwargs)

    instructions = list(dis.get_instructions(fn.__code__))
    _ensure_translatable_ops(instructions)

    for i in instructions:
        verbose_fn(str(i))

    # Must assign_vars before anything else, because dis.Instruction is too
    # hard to work with (i.e. no assignment)
    verbose_fn('\n== Assign vars')
    vis = _vars.assign_vars(instructions)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Fill Line Starts')
    vis = _vars.fill_line_starts(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Pin Globals')
    vis = _folding.pin_globals_to_consts(fn, vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Fold Constants')
    vis = _folding.fold_consts(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Reinterpret const strings')
    vis = _folding.reinterpret_const_strings(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Remove unread constants')
    vis = _folding.remove_unread_consts(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Set dst var types')
    vis = _types.set_dst_var_types(vis, arg_types)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Set src var types')
    vis = _types.set_src_var_types(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== replace arg loads')
    vis = _mem.replace_arg_loads(vis, arg_types)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Convert primitive var types')
    vis = _mem.convert_primitive_var_types(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Remove load consts')
    vis = _mem.replace_load_consts(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Insert fast vars')
    vis = _mem.insert_fast_vars(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Replace fast loads')
    vis = _mem.replace_fast_loads(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Replace fast stores')
    vis = _mem.replace_fast_stores(vis)
    for vi in vis:
        verbose_fn(str(vi))

    verbose_fn('\n== Set stack allocations')
    vis, stack = _stack.set_stack_allocations(vis)
    for vi in vis:
        verbose_fn(str(vi))

    # Must come last, as none of the above knows how to deal with Labels
    verbose_fn('\n== insert labels')
    vis = _labels.insert_labels(vis)
    for vi in vis:
        verbose_fn(str(vi))

    return vis, stack
