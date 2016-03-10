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

import uuid
import os

from tornado.options import options

from storage.backends.file import Index, MPinStorage
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

STORAGE_FILENAME = '/tmp/{0}.json'.format(uuid.uuid4().hex)


def get_storage(*args, **kwargs):
    options.fileStorageLocation = STORAGE_FILENAME
    if os.path.isfile(STORAGE_FILENAME):
        os.remove(STORAGE_FILENAME)
    return MPinStorage(*args, **kwargs)


def test_index():
    index = Index(None, 'a_b', ['a', 'b'])

    assert index.name == 'a_b'
    assert index.fields == ['a', 'b']

    obj = {
        'a': 1,
        'b': 2,
        'c': 3,
    }

    key = index._get_item_key(obj)
    assert key == '1_2'

    class Obj(object):
        a = 1
        b = 2
        c = 3

    key = index._get_item_key(Obj())
    assert key == '1_2'

    obj = {
        'b': 2,
        'c': 3,
    }

    key = index._get_item_key(obj)
    assert not key

    class Obj(object):
        b = 2
        c = 3

    key = index._get_item_key(Obj())
    assert not key


def test_simplekey_index(io_loop):
    storage = get_storage(io_loop, 'id1')
    simplekey_index_case(storage)


def test_multi_indexes(io_loop):
    storage = get_storage(io_loop, 'id1', 'id2')
    multi_indexes_case(storage)


def test_multikey_indexes(io_loop):
    storage = get_storage(io_loop, 'id1,id2')
    multikey_indexes(storage)


def test_mixkey_indexes(io_loop):
    storage = get_storage(io_loop, 'id1', 'id1,id2')
    mixkey_indexes_case(storage)


def test_missing_key_indexes(io_loop):
    storage = get_storage(io_loop, 'id1', 'id2')
    missing_key_indexes_case(storage)


def test_valid_string_date(io_loop):
    storage = get_storage(io_loop, 'id1', 'id2')
    valid_string_date_case(storage)


def test_invalid_string_date(io_loop):
    storage = get_storage(io_loop, 'id1', 'id2')
    invalid_string_date_case(storage)


def test_no_date(io_loop):
    storage = get_storage(io_loop, 'id1', 'id2')
    no_date_case(storage)


def test_item_deletion(io_loop):
    storage = get_storage(io_loop, 'id1', 'id2')
    item_deletion_case(storage)


def test_keys_with_underscore(io_loop):
    storage = get_storage(io_loop, 'id_1', 'id_1,id_2')
    keys_with_underscore_case(storage)


def test_update_item(io_loop):
    storage = get_storage(io_loop, 'id1')
    update_item_case(storage)


def test_reinitialization(io_loop):
    storage = get_storage(io_loop, 'id1')
    simplekey_index_case(storage)

    del storage
    storage = MPinStorage(io_loop, 'id1')

    item1 = storage.find(id1=1.1)
    item2 = storage.find(id1=2.1)

    assert item1.key == 'value1'
    assert item2.key == 'value2'
