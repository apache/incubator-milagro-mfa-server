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

from __future__ import print_function, unicode_literals
from dynamic_options import _test_dynamic_options_update
from rps import DYNAMIC_OPTION_MAPPING


def test_enable_sync():

    _test_dynamic_options_update(
        initial_options={'syncTime': False, 'timePeriod': 1000},
        response_body='{"time_synchronization": true}',
        expected_options={'syncTime': True, 'timePeriod': 1000},
        local_mapping=DYNAMIC_OPTION_MAPPING)


def test_change_period():
    _test_dynamic_options_update(
        initial_options={'syncTime': True, 'timePeriod': 1000},
        response_body='{"time_synchronization_period": 2000}',
        expected_options={'syncTime': True, 'timePeriod': 2000},
        local_mapping=DYNAMIC_OPTION_MAPPING)


def test_disable_sync():
    _test_dynamic_options_update(
        initial_options={'syncTime': True, 'timePeriod': 1000},
        response_body='{"time_synchronization": false}',
        expected_options={'syncTime': False, 'timePeriod': 1000},
        local_mapping=DYNAMIC_OPTION_MAPPING)


def test_set_password_options():
    _test_dynamic_options_update(
        initial_options={'usePassword': "PIN", 'minPasswordLength': 0, 'maxPasswordLength': 100},
        response_body='{"use_password": "either", "min_password_length": 10, "max_password_length": 11}',
        expected_options={'usePassword': "either", 'minPasswordLength': 10, 'maxPasswordLength': 11},
        local_mapping=DYNAMIC_OPTION_MAPPING)


def test_mobile_change():
    _test_dynamic_options_update(
        initial_options={
            "mobileUseNative": True,
            "mobileConfig": [{
                "mobile_otp_name": "Foo",
                "mobile_otp_url": "foo",
                "mobile_otp_type": "otpa",
                "mobile_online_name": "Spam",
                "mobile_online_url": "spam",
                "mobile_online_type": "onlinea",
                "use_password": "PIN",
                "min_password_length": 1,
                "max_password_length": 10,
            }],
        },
        response_body="""
        {
            "mobile_use_native": false,
            "mobile_client_config": [{
                "mobile_otp_name": "Bar",
                "mobile_otp_url": "bar",
                "mobile_otp_type": "otpb",
                "mobile_online_name": "Eggs",
                "mobile_online_url": "eggs",
                "mobile_online_type": "onlineb",
                "use_password": "either",
                "min_password_length": 5,
                "max_password_length": 15
            }]
        }
        """,
        expected_options={
            "mobileUseNative": False,
            "mobileConfig": [{
                "mobile_otp_name": "Bar",
                "mobile_otp_url": "bar",
                "mobile_otp_type": 'otpb',
                "mobile_online_name": "Eggs",
                "mobile_online_url": "eggs",
                "mobile_online_type": "onlineb",
                "use_password": "either",
                "min_password_length": 5,
                "max_password_length": 15,
            }],
        },
        local_mapping=DYNAMIC_OPTION_MAPPING)
