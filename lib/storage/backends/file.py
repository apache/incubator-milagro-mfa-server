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

import datetime
import dateutil.parser
import json
import os.path

from tornado.options import options

from storage.backends.memory import (
    Index as MemoryIndex,
    MPinStorage as MemoryStorage,
)
from storage.item import Item


class MyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()

        elif isinstance(obj, Item):
            return obj.dict

        return json.JSONEncoder.default(self, obj)


class Index(MemoryIndex):
    pass


class MPinStorage(MemoryStorage):
    def __init__(self, *args, **kwargs):
        super(MPinStorage, self).__init__(*args, **kwargs)
        self._deserialize()

    def _storage_change(self):
        self._serialize()

    def _serialize(self):
        data = {
            'expires_list': self._expires_list,
            'items': self._items,
            'indexes': self.indexes,
        }
        json_data = json.dumps(data, cls=MyEncoder)
        with open(options.fileStorageLocation, 'w') as json_storage:
            json_storage.write(json_data)

    def _deserialize_expires_list(self, data):
        return [
            (dateutil.parser.parse(expiration), _id)
            for expiration, _id in data.get('expires_list', [])
        ]

    def _deserialize_items(self, data):
        return dict((
            (_id, Item(self, None, **item_data))
            for _id, item_data in data.get('items', {}).iteritems()
        ))

    def _deserialize_index(self, data):
        indexes = {}
        for index_name, index_data in data.get('indexes', {}).iteritems():
            index = Index(self, index_name, index_name.split(','))
            for key, value in index_data.iteritems():
                index[key] = value

            indexes[index_name] = index

        return indexes

    def _deserialize(self):
        if not os.path.isfile(options.fileStorageLocation):
            return

        with open(options.fileStorageLocation, 'r') as json_storage:
            data = json.load(json_storage)

        self._expires_list = self._deserialize_expires_list(data)
        self._items = self._deserialize_items(data)
        self.indexes = self._deserialize_index(data)

        self._schedule_expiration_check()
