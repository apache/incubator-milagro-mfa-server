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

import json

from tornado.options import options
from tornado.log import app_log as log
from tornado.httpclient import AsyncHTTPClient
from tornado.gen import coroutine


def _extract_options(body, local_mapping):
    try:
        dynamic_options = json.loads(body)
        log.debug(
            "Recieved dynamic options: {0}"
            .format(dynamic_options))
        return dynamic_options
    except Exception as e:
        dynamic_options = {}
        log.error(
            "Can not parse dynamic options, exception: {0}"
            .format(e))
    return dynamic_options


@coroutine
def process_dynamic_options(name_mapping, handlers, application=None, initial=False):
    """
    Process dynamic updates.
    `name_mappings` is a dict in the form `remote_option_name`: `local_option_name`
    `handlers` is a list of callbacks to run after options update
    `application` is the applicatiopn object, that may be needed by some handlers
    `initial` is a boolean flag that tells if the caller is a request handler or main loop
    Handlers signature:
    `updated` is a list of actually updated options (ones that changed value)
    `application` is the application object
    `initial` is the initial flag
    """
    if not options.dynamicOptionsURL:
        log.debug("Dynamic options disabled")
        updated = {}
    else:
        try:
            client = AsyncHTTPClient()
            response = yield client.fetch(options.dynamicOptionsURL)
            dynamic_options = _extract_options(response.body, name_mapping)
            updated = update_dynamic_options(dynamic_options, name_mapping)
        except Exception as e:
            log.error("Error while getting dynamic options")
            log.error(e)
            updated = {}

    for handler in handlers:
        try:
            handler(updated, application, initial)
        except Exception as e:
            log.error("Error while running update handlers")
            log.error(e)


def update_dynamic_options(dynamic_options, local_mapping):
    updated = []
    for remote_name, remote_value in dynamic_options.items():
        if remote_name not in local_mapping:
            log.debug(
                "Recieved unsupported option for sync: {0}"
                .format(remote_name))
            continue
        local_name = local_mapping[remote_name]
        local_value = getattr(options, local_name)
        if local_value != remote_value:
            setattr(options, local_name, remote_value)
            updated.append(local_name)
    log.debug("Dynamic options for update {0}".format(updated))
    return updated


def generate_dynamic_options(local_mapping):
    log.debug("Generating synamic options")
    dynamic_options = {}
    for remote_name, local_name in local_mapping.items():
        dynamic_options[remote_name] = getattr(options, local_name)
    return dynamic_options


def _test_dynamic_options_update(
        initial_options,
        response_body,
        expected_options,
        local_mapping):
    """
    initial_options - dict of initial options to be set.
    response_body - body of the recieved response (expected to be json).
    expected_options - values to be checked in options object after processing.
    local_mapping - local mapping for option names.
    """

    for option, value in initial_options.items():
        setattr(options, option, value)

    dynamic_options = json.loads(response_body)

    update_dynamic_options(dynamic_options, local_mapping)

    for option, value in expected_options.items():
        assert getattr(options, option) == value
