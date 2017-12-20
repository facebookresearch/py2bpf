#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.


class TranslationError(Exception):
    def __init__(self, line, msg):
        super(TranslationError, self).__init__(self, msg)
        self.line, self.msg = line, msg

    def __str__(self):
        return 'Line {}: {}'.format(self.line, self.msg)
