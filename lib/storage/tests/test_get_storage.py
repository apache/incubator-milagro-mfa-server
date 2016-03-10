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

import pytest

from tornado.options import options

from storage import get_storage_cls, StorageError
from storage.backends.memory import MPinStorage as MemoryStorage
from storage.backends.redis import MPinStorage as RedisStorage
from storage.backends.file import MPinStorage as FileStorage


def test_defauld(io_loop):
    storage = get_storage_cls()(io_loop, 'key')
    assert isinstance(storage, MemoryStorage)


def test_memory_defauld(io_loop):
    options.storage = 'memory'
    storage = get_storage_cls()(io_loop, 'key')
    assert isinstance(storage, MemoryStorage)


def test_redis_defauld(io_loop):
    options.storage = 'redis'
    storage = get_storage_cls()(io_loop, 'key')
    assert isinstance(storage, RedisStorage)


def test_file_defauld(io_loop):
    options.storage = 'json'
    options.fileStorageLocation = None
    with pytest.raises(StorageError):
        storage = get_storage_cls()(io_loop, 'key')

    options.fileStorageLocation = 'file.json'
    storage = get_storage_cls()(io_loop, 'key')
    assert isinstance(storage, FileStorage)


def test_invalid_defauld(io_loop):
    options.storage = 'invalid'
    with pytest.raises(SystemExit):
        get_storage_cls()(io_loop, 'key')
