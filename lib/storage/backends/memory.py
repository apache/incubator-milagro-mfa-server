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

import bisect
import datetime

from mpin_utils.common import Time

from storage.backends.base import BaseIndex, BaseStorage


class Index(BaseIndex):

    def _add_item(self, key, obj):
        self[key] = obj._id

    def _find_item(self, key):
        return self.get(key)

    def _delete_item(self, key):
        if key in self:
            del self[key]


class MPinStorage(BaseStorage):
    index_cls = Index

    def __init__(self, *args, **kwargs):
        super(MPinStorage, self).__init__(*args, **kwargs)
        self._expires_list = []
        self._timeout = None
        self._items = {}

    def __len__(self):
        return len(self._items)

    def _add_item(self, item):
        item._active = True
        self._items[item._id] = item
        if item._expiration_datetime:
            bisect.insort_left(self._expires_list, (item._expiration_datetime, item._id))
            self._schedule_expiration_check()

        self._storage_change()

    def _find_item(self, index, **kwargs):
        _id = index.find(**kwargs)
        item = self._items.get(_id)
        if item and item._active:
            return item
        else:
            return None

    def _delete_item(self, item):
        item._active = False

    def _schedule_expiration_check(self):
        if self._timeout:
            self.ioloop.remove_timeout(self._timeout)
            self._timeout = None

        while len(self._expires_list) > 0:
            item_expiration, item_id = self._expires_list[0]

            try:
                item = self._items[item_id]
            except KeyError:
                del self._expires_list[0]
                continue

            now = Time.syncedNow()
            if not item._active or item_expiration < now:
                del self._expires_list[0]
                del self._items[item_id]
                self._delete_from_indexes(item)
                continue

            # No more expired items, schedule next check
            self._timeout = self.ioloop.add_timeout(
                item_expiration - now + datetime.timedelta(milliseconds=100),
                self._schedule_expiration_check
            )
            break

        self._storage_change()
