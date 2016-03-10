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

from storage.item import Item


class BaseIndex(dict):

    def __init__(self, storage, name, fields):
        super(BaseIndex, self).__init__()

        self.storage = storage
        self.name = name
        self.fields = fields[:]

    def _add_item(self, key, obj):
        raise NotImplemented

    def _find_item(self, key):
        raise NotImplemented

    def _delete_item(self, key):
        raise NotImplemented

    def _get_item_key(self, obj):
        key = []
        for field_name in self.fields:
            if type(obj) is dict:
                val = obj.get(field_name)
            else:
                val = getattr(obj, field_name, None)
            # update index only if all the fields have values
            if not val:
                return None
            key.append(str(val))
        return "_".join(key)

    def add(self, obj):
        key = self._get_item_key(obj)
        if key:
            self._add_item(key, obj)

    def find(self, **kwargs):
        key = self._get_item_key(kwargs)
        if key:
            return self._find_item(key)
        else:
            return None

    def delete(self, obj):
        key = self._get_item_key(obj)
        if key:
            self._delete_item(key)


class BaseStorage(object):
    index_cls = BaseIndex

    def __init__(self, ioloop, *indexes):
        '''
        Initialize the in-memory storage and create indexes defined as a list of parameters.
        The indexed fields must be coma-separated.

        Example:
            M = MPinStorage("mpinid", "mpinid,wid") #Will create two indexes: by mpinid and by mpinid and wid
        '''

        self.ioloop = ioloop
        self.indexes = {}

        # Create indexes
        for index in indexes:
            index_fields = map(lambda x: x.strip(), index.split(","))
            index_name = ",".join(index_fields)

            self.indexes[index_name] = self.index_cls(
                storage=self,
                name=index_name,
                fields=index_fields,
            )

    def _add_item(self, item):
        raise NotImplemented

    def _find_item(self, index, **kwargs):
        raise NotImplemented

    def _delete_item(self, item):
        raise NotImplemented

    def _delete_from_indexes(self, item):
        for index in self.indexes.itervalues():
            index.delete(item)

    def _storage_change(self):
        pass

    def update_item(self, item):
        self.update_index(item)
        self._add_item(item)

    def add(self, expire_time=None, **kwargs):
        item = Item(self, expire_time, **kwargs)
        self._add_item(item)
        return item

    def find(self, **kwargs):
        correct_index = None
        for index in self.indexes.itervalues():
            if sorted(kwargs.keys()) == sorted(index.fields):
                correct_index = index
                break

        if correct_index is not None:
            return self._find_item(correct_index, **kwargs)
        else:
            return None

    def delete(self, item):
        self._delete_item(item)
        self._delete_from_indexes(item)

    def update_index(self, item):
        for index in self.indexes.itervalues():
            index.add(item)
