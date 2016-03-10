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

"""Unit tests for crypto mapping functions."""
import calendar
import datetime
import time

from pbkdf2 import PBKDF2

import mpin
import crypto


def test_today():
    """Get today."""
    today = crypto.today()
    assert type(today) == int
    assert today == calendar.timegm(time.gmtime()) / (60 * 1440)


def test_auth_success():
    """Test the basic authentication flow."""
    seed = open('/dev/urandom', 'rb').read(100)
    RNG = crypto.get_random_generator(seed)

    y = crypto.mpin_random_generate(RNG)

    date = 16238
    PIN = 1234
    mpin_id = '{"mobile": 1, "issued": "2013-10-19T06:12:28Z", "userID": "testUser0@certivox.com", "salt": "e0842acc8cc38fc4"}'

    token = "040d73e9b7c746525edbb90e042a6b8f6e41e2417a0c0c1600f8b693c0b6c0bbce0c61b73100798c7505b3eb12c2393187355145090333f904fd896684ec4990d3".decode("hex")
    timePermit = "0408ba13483e817626a45be598b1b89296aa805a6aa31e98503321c30d7177711a1c98a77cbf8edf2497d0f5f7593c72457b36cd3e4f19e1f3c5636c0ca7a1817d".decode("hex")
    serverSecret = "0d5a0bb4621c4eec9ee28b0339047e7afdaae87c5f0f972253f2e90f55dbda4a16efc98cb3b925d4237a14527b1db361f460dae271f115c28ff5f3ef5fb5dae20a8ccc12bea3fc3f5911853eff3642e649140fcf0892a13ec8b22e94a750a2930c64f5792a22bc01580cbd041c7a8c21659abacead12fd4460f17b27f5940d4d".decode("hex")

    # Client part
    Y = mpin.ffi.new("octet*")
    Yval = mpin.ffi.new("char [%s]" % len(y), y)
    Y[0].val = Yval
    Y[0].max = len(y)
    Y[0].len = len(y)

    MPIN_ID = mpin.ffi.new("octet*")
    MPIN_IDval = mpin.ffi.new("char [%s]" % len(mpin_id), mpin_id)
    MPIN_ID[0].val = MPIN_IDval
    MPIN_ID[0].max = len(mpin_id)
    MPIN_ID[0].len = len(mpin_id)

    TOKEN = mpin.ffi.new("octet*")
    TOKENval = mpin.ffi.new("char [%s]" % len(token), token)
    TOKEN[0].val = TOKENval
    TOKEN[0].len = len(token)
    TOKEN[0].max = len(token)

    X = mpin.ffi.new("octet*")
    Xval = mpin.ffi.new("char []", mpin.PGS)
    X[0].val = Xval
    X[0].max = mpin.PGS
    X[0].len = mpin.PGS

    CLIENT_SECRET = mpin.ffi.new("octet*")
    CLIENT_SECRETval = mpin.ffi.new("char []", mpin.G1)
    CLIENT_SECRET[0].val = CLIENT_SECRETval
    CLIENT_SECRET[0].max = mpin.G1
    CLIENT_SECRET[0].len = mpin.G1

    U = mpin.ffi.new("octet*")
    Uval = mpin.ffi.new("char []", mpin.G1)
    U[0].val = Uval
    U[0].max = mpin.G1
    U[0].len = mpin.G1

    UT = mpin.ffi.new("octet*")
    UTval = mpin.ffi.new("char []", mpin.G1)
    UT[0].val = UTval
    UT[0].max = mpin.G1
    UT[0].len = mpin.G1

    TIMEPERMIT = mpin.ffi.new("octet*")
    TIMEPERMITval = mpin.ffi.new("char [%s]" % len(timePermit), timePermit)
    TIMEPERMIT[0].val = TIMEPERMITval
    TIMEPERMIT[0].len = len(timePermit)
    TIMEPERMIT[0].max = len(timePermit)

    # Client first pass
    rtn = mpin.libmpin.MPIN_CLIENT_1(date, MPIN_ID, RNG, X, PIN, TOKEN, CLIENT_SECRET, U, UT, TIMEPERMIT)
    assert rtn == 0

    # Client second pass
    rtn = mpin.libmpin.MPIN_CLIENT_2(X, Y, CLIENT_SECRET)
    assert rtn == 0

    # Server second pass
    hid, htid = crypto.mpin_server_1(mpin_id, date)
    success_code, _, _ = crypto.mpin_server_2(
        serverSecret,
        mpin.toHex(CLIENT_SECRET).decode('hex'),
        date, hid, htid,
        mpin.toHex(Y).decode('hex'),
        mpin.toHex(U).decode('hex'),
        mpin.toHex(UT).decode('hex'))
    assert success_code == 0


def test_encrypt_decrypt_master_secret():
    """Test encryption/decription of master secret."""
    seed = open('/dev/urandom', 'rb').read(100)

    rng = crypto.get_random_generator(seed)
    now = datetime.datetime.now()

    aes_key = PBKDF2('passphrase', 'salt').read(16)

    ciphertext_hex, iv_hex, tag_hex = crypto.aes_gcm_encrypt('master_secret', aes_key, rng, now.strftime('%Y-%m-%dT%H:%M:%SZ'))

    tag, plaintext = crypto.aes_gcm_decrypt(
        aes_key=aes_key,
        iv=str(iv_hex.decode('hex')),
        header=str(now.strftime('%Y-%m-%dT%H:%M:%SZ')),
        ciphertext=str(ciphertext_hex.decode('hex')))

    assert tag == tag_hex
    assert plaintext.decode('hex') == 'master_secret'
