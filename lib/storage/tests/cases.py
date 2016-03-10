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

"""Common test cases for storage."""
from __future__ import division, absolute_import, print_function, unicode_literals

from datetime import datetime, timedelta

import pytest


def simplekey_index_case(storage):
    """
    indexes = 'id1'
    """

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=2.1,
        id2=2.2,
        key='value2'
    )

    item1 = storage.find(id1=1.1)
    item2 = storage.find(id1=2.1)

    assert item1.key == 'value1'
    assert item2.key == 'value2'
    assert not storage.find(id2=1.2)  # Log warning at this point

    storage.delete(item1)
    assert not storage.find(id1=1.1)
    assert storage.find(id1=2.1)


def multi_indexes_case(storage):
    """
    indexes = 'id1', 'id2'
    """

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=2.1,
        id2=2.2,
        key='value2'
    )

    assert storage.find(id1=1.1).key == 'value1'
    assert storage.find(id2=2.2).key == 'value2'

    assert not storage.find(id1=2.1, id2=2.2)
    assert not storage.find(id1=1.1, id2=2.2)
    assert not storage.find(id1=1.1, id2=2.2)
    assert not storage.find(id1=2.1, key='value2')


def multikey_indexes(storage):
    """
    indexes = 'id1,id2'
    """

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=2.1,
        id2=2.2,
        key='value2'
    )

    assert storage.find(id1=2.1, id2=2.2).key == 'value2'
    assert not storage.find(id1=1.1)
    assert not storage.find(id1=1.1, id2=2.2)
    assert not storage.find(id1=2.1, key='value2')


def mixkey_indexes_case(storage):
    """
    indexes = 'id1', 'id1,id2'
    """

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=2.1,
        id2=2.2,
        key='value2'
    )

    assert storage.find(id1=2.1, id2=2.2).key == 'value2'
    assert storage.find(id1=1.1).key == 'value1'
    assert not storage.find(id2=2.2)
    assert not storage.find(id1=1.1, id2=2.2)
    assert not storage.find(id1=2.1, key='value2')


def missing_key_indexes_case(storage):
    """
    indexes = 'id1', 'id2'
    """

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=2.1,
        key='value2'
    )

    assert storage.find(id1=1.1).key == 'value1'
    assert storage.find(id2=1.2).key == 'value1'
    assert storage.find(id1=2.1).key == 'value2'

    assert not storage.find(id2=2.2)

    item2 = storage.find(id1=2.1)
    storage.delete(item2)
    assert not storage.find(id1=2.1)


def valid_string_date_case(storage):
    """
    indexes = 'id1', 'id2'
    """

    storage.add(
        (datetime.now() + timedelta(days=1)).isoformat(),
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        (datetime.now() + timedelta(days=1)).isoformat(),
        id1=2.1,
        id2=2.2,
        key='value2'
    )

    assert storage.find(id1=2.1).key == 'value2'
    assert storage.find(id2=1.2).key == 'value1'


def invalid_string_date_case(storage):
    """
    indexes = 'id1', 'id2'
    """

    with pytest.raises(ValueError):
        storage.add(
            'invalid date',
            id1=1.1,
            id2=1.2,
            key='value1'
        )

    assert not storage.find(id1=1.1)


def no_date_case(storage):
    """
    indexes = 'id1', 'id2'
    """

    storage.add(
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        id1=2.1,
        id2=2.2,
        key='value2'
    )

    assert storage.find(id1=2.1).key == 'value2'
    assert storage.find(id2=1.2).key == 'value1'


def item_deletion_case(storage):
    """
    indexes = 'id1', 'id2'
    """

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=1.1,
        id2=1.2,
        key='value1'
    )

    storage.add(
        datetime.now() + timedelta(days=1),
        id1=2.1,
        key='value2'
    )

    assert storage.find(id1=1.1).key == 'value1'
    assert storage.find(id2=1.2).key == 'value1'
    assert storage.find(id1=2.1).key == 'value2'
    assert not storage.find(id2=2.2)

    item1 = storage.find(id1=1.1)
    storage.delete(item1)

    # try to delete item that does not exist in index
    storage.delete(item1)

    assert not storage.find(id1=1.1)
    assert not storage.find(id2=1.2)
    assert storage.find(id1=2.1).key == 'value2'
    assert not storage.find(id2=2.2)


def keys_with_underscore_case(storage):
    """
    indexes = 'id_1', 'id_1,id_2'
    """

    storage.add(
        datetime.now() + timedelta(days=1),
        id_1=1.1,
        id_2=1.2,
        key='value1'
    )

    storage.add(
        datetime.now() + timedelta(days=1),
        id_1=2.1,
        id_2=2.2,
        key='value2'
    )

    assert storage.find(id_1=2.1, id_2=2.2).key == 'value2'
    assert storage.find(id_1=1.1).key == 'value1'
    assert not storage.find(id_2=2.2)
    assert not storage.find(id_1=1.1, id_2=2.2)
    assert not storage.find(id_1=2.1, key='value2')


def update_item_case(storage):
    """
    indexes = 'id1'
    """
    storage.add(
        datetime.now() + timedelta(days=1),
        id1=1.1,
        id2=1.2,
        key='value'
    )

    item = storage.find(id1=1.1)

    item.update(key='value_new')
    item = storage.find(id1=1.1)
    assert item.key == 'value_new'

    item.update(id1=1.11)
    item = storage.find(id1=1.11)
    assert item.key == 'value_new'

    item.update(key=None)
    item = storage.find(id1=1.11)
    assert not item.key

    item.update(key='value', key1='value1')
    item = storage.find(id1=1.11)
    assert item.key == 'value'
    assert item.key1 == 'value1'

    item.delete()
    item = storage.find(id1=1.11)
    assert not item
