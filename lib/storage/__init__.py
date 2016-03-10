#! /usr/bin/python
#
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

import sys

from tornado.options import define, options
from tornado.log import app_log as log


define("storage", default="memory")

define("redisHost", default="127.0.0.1")
define("redisPort", default=6379)
define("redisDB", default=0)
define("redisPassword", default=None)
define("redisPrefix", default="mpin")

define("fileStorageLocation", type=unicode)


class StorageError(Exception):
    pass


def get_storage_cls():
    if options.storage == "redis":
        from storage.backends.redis import MPinStorage
    elif options.storage == "memory":
        from storage.backends.memory import MPinStorage
    elif options.storage == "json":
        if not options.fileStorageLocation:
            raise StorageError('File storage requires fileStorageLocation option')
        from storage.backends.file import MPinStorage
    else:
        log.error("Invalid storage: {0}".format(options.storage))
        sys.exit(1)

    return MPinStorage
