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

from mpin_utils.common import signMessage, verifySignature


def test_signing_valid():
    message = 'Hello world!'
    key = 'super secret'
    expected_signature = 'f577954ea54f8e8cc1b7d5d238dde635a783a3a37a4ba44877e9f63269cd4b53'

    signature = signMessage(message, key)

    assert signature == expected_signature

    valid, reason, code = verifySignature(message, signature, key)

    assert valid
    assert reason == 'Valid signature'
    assert code == 200


def test_signing_invalid():
    message = 'Hello world!'
    key = 'super secret'
    signature = 'invalid signature'

    valid, reason, code = verifySignature(message, signature, key)

    assert not valid
    assert reason == 'Invalid signature'
    assert code == 401
