# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import division, absolute_import, print_function, unicode_literals

import fakeredis

from storage.backends.redis import MPinStorage
from storage.tests.cases import (
    simplekey_index_case,
    multi_indexes_case,
    multikey_indexes,
    mixkey_indexes_case,
    missing_key_indexes_case,
    valid_string_date_case,
    invalid_string_date_case,
    no_date_case,
    item_deletion_case,
    keys_with_underscore_case,
    update_item_case,
)


def get_storage(*args, **kwargs):
    storage = MPinStorage(*args, **kwargs)
    storage.redis.redis = fakeredis.FakeStrictRedis()
    storage.redis.redis.flushdb()
    return storage


def test_simplekey_index(io_loop):
    simplekey_index_case(get_storage(io_loop, 'id1'))


def test_multi_indexes(io_loop):
    multi_indexes_case(get_storage(io_loop, 'id1', 'id2'))


def test_multikey_indexes(io_loop):
    multikey_indexes(get_storage(io_loop, 'id1,id2'))


def test_mixkey_indexes(io_loop):
    mixkey_indexes_case(get_storage(io_loop, 'id1', 'id1,id2'))


def test_missing_key_indexes(io_loop):
    missing_key_indexes_case(get_storage(io_loop, 'id1', 'id2'))


def test_valid_string_date(io_loop):
    valid_string_date_case(get_storage(io_loop, 'id1', 'id2'))


def test_invalid_string_date(io_loop):
    invalid_string_date_case(get_storage(io_loop, 'id1', 'id2'))


def test_no_date(io_loop):
    no_date_case(get_storage(io_loop, 'id1', 'id2'))


def test_item_deletion(io_loop):
    item_deletion_case(get_storage(io_loop, 'id1', 'id2'))


def test_keys_with_underscore(io_loop):
    keys_with_underscore_case(get_storage(io_loop, 'id_1', 'id_1,id_2'))


def test_update_item(io_loop):
    update_item_case(get_storage(io_loop, 'id1'))
