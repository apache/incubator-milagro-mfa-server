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

import datetime
import json
import uuid

from mpin_utils.common import Time


class Item(object):

    def __init__(self, storage, expire_time, **kwargs):
        '''expireTime should be in ISO format'''
        self.__fields = ["_id", "_active", "_expires"]
        self.__storage = storage

        self._id = uuid.uuid1().hex

        if isinstance(expire_time, datetime.datetime):
            self._expires = expire_time.isoformat()
        else:
            self._expires = expire_time

        self._update_item(**kwargs)

        self._expiration_datetime = None
        if self._expires:
            self._expiration_datetime = Time.ISOtoDateTime(self._expires)

        self.__storage.update_index(self)

    def __getattr__(self, name):
        return None

    def __str__(self):
        return "\n".join([
            "{0}: {1}".format(k, getattr(self, k)) for k in self.__fields
        ])

    def _update_item(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
            if key in self.__fields:
                if not value:
                    self.__fields.remove(key)
            else:
                self.__fields.append(key)

    @property
    def dict(self):
        return dict([(k, getattr(self, k)) for k in self.__fields])

    @property
    def json(self):
        return json.dumps(self.dict)

    def update(self, **kwargs):
        self._update_item(**kwargs)
        self.__storage.update_item(self)

    def delete(self):
        self.__storage.delete(self)
