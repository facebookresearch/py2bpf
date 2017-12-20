#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import resource


def ensure_resources():
    resource.setrlimit(
        resource.RLIMIT_MEMLOCK,
        (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
