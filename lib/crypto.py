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

"""Wrapper function for mpin library."""
import mpin
import datetime
from mpin_utils.common import Time

# AES-GCM Key size
PAS = mpin.PAS


class CryptoError(Exception):

    """Exception raises by crypto module."""

    pass


def today():
    """Return time in slots since epoch using synced time"""
    utc_dt = datetime.datetime.utcfromtimestamp(0)
    return int((Time.syncedNow() - utc_dt).total_seconds() / 86400)


def get_random_generator(seed):
    """Return random number generator."""
    SEED = mpin.ffi.new('octet*')
    SEED_val = mpin.ffi.new('char [%s]' % len(seed), seed)
    SEED[0].val = SEED_val
    SEED[0].len = len(seed)
    SEED[0].max = len(seed)

    # random number generator
    RNG = mpin.ffi.new('csprng*')
    mpin.libmpin.MPIN_CREATE_CSPRNG(RNG, SEED)

    return RNG


def random_generate(rng, length):
    """Generate random number with predefined length."""
    OTT = mpin.ffi.new('octet*')
    OTTval = mpin.ffi.new('char []', length)
    OTT[0].val = OTTval
    OTT[0].max = length
    OTT[0].len = length

    mpin.libmpin.generateRandom(rng, OTT)
    return mpin.toHex(OTT)


def generate_otp(rng):
    """Generate One time password."""
    return mpin.libmpin.generateOTP(rng)


def mpin_random_generate(rng):
    """Generate random secret."""
    MASTER_SECRET = mpin.ffi.new('octet*')
    MASTER_SECRET_val = mpin.ffi.new('char []', mpin.PGS)
    MASTER_SECRET[0].val = MASTER_SECRET_val
    MASTER_SECRET[0].max = mpin.PGS
    MASTER_SECRET[0].len = mpin.PGS

    rtn = mpin.libmpin.MPIN_RANDOM_GENERATE(rng, MASTER_SECRET)
    if rtn != 0:
        raise CryptoError(rtn)

    master_secret_hex = mpin.toHex(MASTER_SECRET)
    return master_secret_hex.decode('hex')


def aes_gcm_encrypt(master_secret, aes_key, rand, header, iv=mpin.IVL):
    """Encrypt master secret."""
    # AES Key
    AES_KEY = mpin.ffi.new('octet*')
    AES_KEY_val = mpin.ffi.new('char [%s]' % len(aes_key), aes_key)
    AES_KEY[0].val = AES_KEY_val
    AES_KEY[0].max = len(aes_key)
    AES_KEY[0].len = len(aes_key)

    # Initialisation Vector
    IV = mpin.ffi.new('octet*')
    IV_val = mpin.ffi.new('char []', iv)
    IV[0].val = IV_val
    IV[0].max = iv
    IV[0].len = iv
    mpin.libmpin.generateRandom(rand, IV)

    # Authentication tag
    TAG = mpin.ffi.new('octet*')
    TAG_val = mpin.ffi.new('char []', mpin.PAS)
    TAG[0].val = TAG_val
    TAG[0].max = mpin.PAS

    # Header
    HEADER = mpin.ffi.new('octet*')
    HEADER_val = mpin.ffi.new('char [%s]' % len(header), header)
    HEADER[0].val = HEADER_val
    HEADER[0].max = len(header)
    HEADER[0].len = len(header)

    # Plaintext input
    plaintext = master_secret
    PLAINTEXT = mpin.ffi.new('octet*')
    PLAINTEXT_val = mpin.ffi.new('char [%s]' % len(plaintext), plaintext)
    PLAINTEXT[0].val = PLAINTEXT_val
    PLAINTEXT[0].max = len(plaintext)
    PLAINTEXT[0].len = len(plaintext)

    # Ciphertext
    CIPHERTEXT = mpin.ffi.new('octet*')
    CIPHERTEXT_val = mpin.ffi.new('char []', len(plaintext))
    CIPHERTEXT[0].val = CIPHERTEXT_val
    CIPHERTEXT[0].max = len(plaintext)

    mpin.libmpin.MPIN_AES_GCM_ENCRYPT(AES_KEY, IV, HEADER, PLAINTEXT, CIPHERTEXT, TAG)
    IV_hex = mpin.toHex(IV)
    CIPHERTEXT_hex = mpin.toHex(CIPHERTEXT)
    TAG_hex = mpin.toHex(TAG)

    return CIPHERTEXT_hex, IV_hex, TAG_hex


def aes_gcm_decrypt(aes_key, iv, header, ciphertext):
    """AES GCM Decrypt."""
    # AES Key
    AES_KEY = mpin.ffi.new('octet*')
    AES_KEY_val = mpin.ffi.new('char [%s]' % len(aes_key), aes_key)
    AES_KEY[0].val = AES_KEY_val
    AES_KEY[0].max = len(aes_key)
    AES_KEY[0].len = len(aes_key)

    # Initialization Vector
    IV = mpin.ffi.new('octet*')
    IV_val = mpin.ffi.new('char [%s]' % len(iv), iv)
    IV[0].val = IV_val
    IV[0].max = len(iv)
    IV[0].len = len(iv)

    # Header
    HEADER = mpin.ffi.new('octet*')
    HEADER_val = mpin.ffi.new('char [%s]' % len(header), header)
    HEADER[0].val = HEADER_val
    HEADER[0].max = len(header)
    HEADER[0].len = len(header)

    # Ciphertext
    CIPHERTEXT = mpin.ffi.new('octet*')
    CIPHERTEXT_val = mpin.ffi.new('char [%s]' % len(ciphertext), ciphertext)
    CIPHERTEXT[0].val = CIPHERTEXT_val
    CIPHERTEXT[0].max = len(ciphertext)
    CIPHERTEXT[0].len = len(ciphertext)

    # Plaintext
    PLAINTEXT = mpin.ffi.new('octet*')
    PLAINTEXT_val = mpin.ffi.new('char []', CIPHERTEXT[0].len)
    PLAINTEXT[0].val = PLAINTEXT_val
    PLAINTEXT[0].max = CIPHERTEXT[0].len
    PLAINTEXT[0].len = CIPHERTEXT[0].len

    # Authentication tag
    TAG = mpin.ffi.new('octet*')
    TAG_val = mpin.ffi.new('char []', mpin.PAS)
    TAG[0].val = TAG_val
    TAG[0].max = mpin.PAS

    # Decrypt ciphertext
    mpin.libmpin.MPIN_AES_GCM_DECRYPT(AES_KEY, IV, HEADER, CIPHERTEXT, PLAINTEXT, TAG)

    return mpin.toHex(TAG), mpin.toHex(PLAINTEXT)


def get_server_secret(master_secret):
    """Generate secret secret."""
    MASTER_SECRET = mpin.ffi.new('octet*')
    MASTER_SECRET_val = mpin.ffi.new('char [%s]' % len(master_secret), master_secret)
    MASTER_SECRET[0].val = MASTER_SECRET_val
    MASTER_SECRET[0].max = len(master_secret)
    MASTER_SECRET[0].len = len(master_secret)

    SERVER_SECRET = mpin.ffi.new('octet*')
    SERVER_SECRET_val = mpin.ffi.new('char []', mpin.G2)
    SERVER_SECRET[0].val = SERVER_SECRET_val
    SERVER_SECRET[0].max = mpin.G2
    SERVER_SECRET[0].len = mpin.G2

    rtn = mpin.libmpin.MPIN_GET_SERVER_SECRET(MASTER_SECRET, SERVER_SECRET)
    if rtn != 0:
        raise CryptoError(rtn)
    return mpin.toHex(SERVER_SECRET)


def get_client_multiple(master_secret, mpin_id):
    """Generate client secret."""
    MASTER_SECRET = mpin.ffi.new('octet*')
    MASTER_SECRET_val = mpin.ffi.new('char [%s]' % len(master_secret), master_secret)
    MASTER_SECRET[0].val = MASTER_SECRET_val
    MASTER_SECRET[0].max = len(master_secret)
    MASTER_SECRET[0].len = len(master_secret)

    CLIENT_SECRET = mpin.ffi.new('octet*')
    CLIENT_SECRET_val = mpin.ffi.new('char []', mpin.G1)
    CLIENT_SECRET[0].val = CLIENT_SECRET_val
    CLIENT_SECRET[0].max = mpin.G1
    CLIENT_SECRET[0].len = mpin.G1

    HASH_MPIN_ID = mpin.ffi.new('octet*')
    HASH_MPIN_ID_val = mpin.ffi.new('char [%s]' % len(mpin_id), mpin_id)
    HASH_MPIN_ID[0].val = HASH_MPIN_ID_val
    HASH_MPIN_ID[0].max = len(mpin_id)
    HASH_MPIN_ID[0].len = len(mpin_id)

    rtn = mpin.libmpin.MPIN_GET_CLIENT_SECRET(MASTER_SECRET, HASH_MPIN_ID, CLIENT_SECRET)
    if rtn != 0:
        raise CryptoError(rtn)
    return mpin.toHex(CLIENT_SECRET)


def get_time_permit(master_secret, mpin_id, date=None):
    """Generate client time permit."""
    MASTER_SECRET = mpin.ffi.new('octet*')
    MASTER_SECRET_val = mpin.ffi.new('char [%s]' % len(master_secret), master_secret)
    MASTER_SECRET[0].val = MASTER_SECRET_val
    MASTER_SECRET[0].max = len(master_secret)
    MASTER_SECRET[0].len = len(master_secret)

    TIME_PERMIT = mpin.ffi.new('octet*')
    TIME_PERMIT_val = mpin.ffi.new('char []', mpin.G1)
    TIME_PERMIT[0].val = TIME_PERMIT_val
    TIME_PERMIT[0].max = mpin.G1
    TIME_PERMIT[0].len = mpin.G1

    HASH_MPIN_ID = mpin.ffi.new('octet*')
    HASH_MPIN_ID_val = mpin.ffi.new('char [%s]' % len(mpin_id), mpin_id)
    HASH_MPIN_ID[0].val = HASH_MPIN_ID_val
    HASH_MPIN_ID[0].max = len(mpin_id)
    HASH_MPIN_ID[0].len = len(mpin_id)

    date = date or today()
    rtn = mpin.libmpin.MPIN_GET_CLIENT_PERMIT(date, MASTER_SECRET, HASH_MPIN_ID, TIME_PERMIT)
    if rtn != 0:
        raise CryptoError(rtn)
    return mpin.toHex(TIME_PERMIT)


def mpin_recombine_g2(certivox_server_secret, customer_server_secret):
    """Recombine server secret."""
    SS1 = mpin.ffi.new("octet*")
    SS1_val = mpin.ffi.new("char [%s]" % len(certivox_server_secret), certivox_server_secret)
    SS1[0].val = SS1_val
    SS1[0].max = mpin.G2
    SS1[0].len = len(certivox_server_secret)

    SS2 = mpin.ffi.new("octet*")
    SS2_val = mpin.ffi.new("char [%s]" % len(customer_server_secret), customer_server_secret)
    SS2[0].val = SS2_val
    SS2[0].max = mpin.G2
    SS2[0].len = len(customer_server_secret)

    SERVER_SECRET = mpin.ffi.new("octet*")
    SERVER_SECRET_val = mpin.ffi.new("char []", mpin.G2)
    SERVER_SECRET[0].val = SERVER_SECRET_val
    SERVER_SECRET[0].max = mpin.G2
    SERVER_SECRET[0].len = mpin.G2

    rtn = mpin.libmpin.MPIN_RECOMBINE_G2(SS1, SS2, SERVER_SECRET)
    if rtn != 0:
        raise CryptoError(rtn)
    return mpin.toHex(SERVER_SECRET)


def mpin_server_1(mpin_id, date):
    """Calculate HID and HTOD."""
    HID = mpin.ffi.new("octet*")
    HIDval = mpin.ffi.new("char []", mpin.G1)
    HID[0].val = HIDval
    HID[0].max = mpin.G1
    HID[0].len = mpin.G1

    # H(T|H(ID))
    HTID = mpin.ffi.new("octet*")
    HTIDval = mpin.ffi.new("char []", mpin.G1)
    HTID[0].val = HTIDval
    HTID[0].max = mpin.G1
    HTID[0].len = mpin.G1

    MPIN_ID = mpin.ffi.new("octet*")
    MPIN_ID_val = mpin.ffi.new("char [%s]" % len(mpin_id), mpin_id)
    MPIN_ID[0].val = MPIN_ID_val
    MPIN_ID[0].max = len(mpin_id)
    MPIN_ID[0].len = len(mpin_id)

    mpin.libmpin.MPIN_SERVER_1(date, MPIN_ID, HID, HTID)

    return mpin.toHex(HID).decode('hex'), mpin.toHex(HTID).decode('hex')


def mpin_server_2(server_secret, v, date, hid, htid, y, u, ut):
    """Check credentials."""
    SERVER_SECRET = mpin.ffi.new("octet*")
    SERVER_SECRET_val = mpin.ffi.new("char [%s]" % len(server_secret), server_secret)
    SERVER_SECRET[0].val = SERVER_SECRET_val
    SERVER_SECRET[0].max = mpin.G2
    SERVER_SECRET[0].len = len(server_secret)

    V = mpin.ffi.new("octet*")
    V_val = mpin.ffi.new("char [%s]" % len(v), v)
    V[0].val = V_val
    V[0].max = len(v)
    V[0].len = len(v)

    lenEF = 12 * mpin.PFS
    E = mpin.ffi.new("octet*")
    Eval = mpin.ffi.new("char []", lenEF)
    E[0].val = Eval
    E[0].max = lenEF
    E[0].len = lenEF

    F = mpin.ffi.new("octet*")
    Fval = mpin.ffi.new("char []", lenEF)
    F[0].val = Fval
    F[0].max = lenEF
    F[0].len = lenEF

    HID = mpin.ffi.new("octet*")
    HIDval = mpin.ffi.new("char [%s]" % len(hid), hid)
    HID[0].val = HIDval
    HID[0].max = len(hid)
    HID[0].len = len(hid)

    # H(T|H(ID))
    HTID = mpin.ffi.new("octet*")
    HTIDval = mpin.ffi.new("char [%s]" % len(htid), htid)
    HTID[0].val = HTIDval
    HTID[0].max = len(htid)
    HTID[0].len = len(htid)

    # Client part
    Y = mpin.ffi.new("octet*")
    Yval = mpin.ffi.new("char [%s]" % len(y), y)
    Y[0].val = Yval
    Y[0].max = len(y)
    Y[0].len = len(y)

    U = mpin.ffi.new("octet*")
    Uval = mpin.ffi.new("char [%s]" % len(u), u)
    U[0].val = Uval
    U[0].max = len(u)
    U[0].len = len(u)

    UT = mpin.ffi.new("octet*")
    UTval = mpin.ffi.new("char [%s]" % len(ut), ut)
    UT[0].val = UTval
    UT[0].max = len(ut)
    UT[0].len = len(ut)

    return mpin.libmpin.MPIN_SERVER_2(date, HID, HTID, Y, SERVER_SECRET, U, UT, V, E, F), mpin.toHex(E), mpin.toHex(F)
