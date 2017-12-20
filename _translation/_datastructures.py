#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


class RuntimeDatastructure:
    '''A type that we shouldn't try to fold (for example, a BpfMap)'''
    pass


class FileDescriptorDatastructure(RuntimeDatastructure):
    '''A type that should reduce to a MapFdImm in bpf'''
    pass
