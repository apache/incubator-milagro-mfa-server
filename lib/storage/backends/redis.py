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

import json

import redis

from tornado.options import options

from mpin_utils.common import Time

from storage.item import Item
from storage.backends.base import BaseIndex, BaseStorage


def get_redis_id(key):
    return '_'.join([options.redisPrefix, key])


class RedisConnection(object):

    def __init__(self, host, port, password, db):
        self.redis = redis.StrictRedis(host, port, password, db)

    def _execute(self, command, *args, **kwargs):
        method = getattr(self.redis, command)
        return method(*args, **kwargs)

    def add(self, key, expires, value):
        if expires:
            self._execute("setex", key, (expires - Time.syncedNow()), value)
        else:
            self._execute("set", key, value)

    def get(self, key):
        return self._execute("get", key)

    def delete(self, key):
        return self._execute("delete", key)


class Index(BaseIndex):

    def _get_item_key(self, obj):
        key = super(Index, self)._get_item_key(obj)
        if key:
            return get_redis_id(key)
        else:
            return None

    def _add_item(self, key, obj):
        self.storage.redis.add(key, obj._expiration_datetime, obj._id)

    def _find_item(self, key):
        return self.storage.redis.get(key)

    def _delete_item(self, key):
        self.storage.redis.delete(key)


class MPinStorage(BaseStorage):
    index_cls = Index

    def __init__(self, *args, **kwargs):
        super(MPinStorage, self).__init__(*args, **kwargs)
        self.redis = RedisConnection(
            host=options.redisHost,
            port=options.redisPort,
            password=options.redisPassword,
            db=options.redisDB
        )

    def _add_item(self, item):
        self.redis.add(
            get_redis_id(item._id),
            item._expiration_datetime,
            item.json
        )

    def _find_item(self, index, **kwargs):
        _id = index.find(**kwargs)
        if not _id:
            return None

        data = self.redis.get(get_redis_id(_id))
        return Item(self, None, **json.loads(data))

    def _delete_item(self, item):
        self.redis.delete(get_redis_id(item._id))
