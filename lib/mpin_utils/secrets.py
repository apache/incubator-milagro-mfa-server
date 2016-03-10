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

"""Utility functions for working with secrets."""
from __future__ import division, absolute_import, print_function, unicode_literals

import json
import os
import time

from pbkdf2 import PBKDF2

import tornado
from tornado.httputil import url_concat
from tornado.log import app_log as log
from tornado.options import define, options

import crypto
from mpin_utils.common import (
    fetchConfig,
    Keys,
    SIGNATURE_EXPIRES_OFFSET_SECONDS,
    signMessage,
    Time,
)


today = crypto.today


def generate_aes_key(passphrase, salt):
    """Return AES key (128 bit) using a pass-phrase.

    It uses the passphrase argument or in its absence asks the user for
    a pass-phrase to derive an AES key. The algorithm used is
    Password-Based Key Derivation Function 2 (PBKDF2)

    Keyword arguments:
        passphrase  -- A string used to generate an AES key
        salt        -- Salt value for the PBKDF2 Algorithm. 64 bits hex encoded
    """
    return PBKDF2(passphrase, str(salt)).read(16)


def backup_master_secret(master_secret, encrypt_master_secret, passphrase, salt, backup_file, time, rng):
    """Write the master secret to file."""
    aes_key = generate_aes_key(passphrase, salt)
    data = {
        'startTime': time.strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    if encrypt_master_secret:
        ciphertext_hex, iv_hex, tag_hex = crypto.aes_gcm_encrypt(
            master_secret, aes_key, rng, time.strftime('%Y-%m-%dT%H:%M:%SZ'))
        data.update({
            'IV': iv_hex,
            'ciphertext': ciphertext_hex,
            'tag': tag_hex})
    else:
        data['master_secret_hex'] = master_secret.encode('hex'),

    with open(backup_file, 'w') as json_file:
        json.dump(data, json_file)


def generate_random_number(rng, length):
    """Return random number with predefined length."""
    return crypto.random_generate(rng, length)


def generate_ott(length, rng, encoding=None):
    """Generate a one time token (OTT).

    Uses the Random Number Generator to generate a value
    of length OTTLength set in the config file. This is
    then encoded.
    """
    ott_hex = generate_random_number(rng, length)
    if encoding == 'hex':
        return ott_hex

    ott = ott_hex.decode('hex')
    if encoding:
        ott = ott.encode(encoding)
    return ott


def generate_otp(rng):
    """Generate a one time password (OTP).

    Uses the Random Number Generator to generate 6 long value
    """
    return crypto.generate_otp(rng)


def get_checksum(num, length):
    """Return checksum."""
    sum_digits = sum([
        int(digit) * (length + 1 - i)
        for i, digit in enumerate(str(num).zfill(length))])
    checksum = (11 - (sum_digits % 11)) % 11
    return checksum if checksum != 10 else None


def generate_random_webid(rng, use_checksum=True):
    """Generate a web identifier for mobile login.

    Generates a random six digit integer. This is
    appended with a one digit checksum.
    """
    num = generate_otp(rng)
    checksum = get_checksum(num, 6) if use_checksum else ''

    if not checksum and use_checksum:
        return None

    return "{0:06d}{1}".format(num, checksum)


def generate_auth_ott(rng):
    """Return auth OTT."""
    return generate_random_number(rng, crypto.PAS)


class SecretsError(Exception):

    """Exception raises by secrets module."""

    pass


class MasterSecret(object):

    """Master Secret."""

    master_secret = None
    start_time = None

    def __init__(self, passphrase, salt, seed, time, backup_file=None, encrypt_master_secret=True):
        """Constructor."""
        self.rng = crypto.get_random_generator(seed)
        self.master_secret, self.start_time = self._get_master_secret(
            passphrase, salt, time, backup_file, encrypt_master_secret)

    def _get_master_secret(self, passphrase, salt, time, backup_file=None, encrypt_master_secret=True):
        """Restore/generate master secret.

        Restore from backup_file if such is provided, generate new otherwise.
        Set backup_file=None for in memory master_secret.
        """
        if not backup_file:
            log.info('Master Secret Share not backed up to file')
            return self._generate_master_secret(), time

        if not os.path.exists(backup_file):
            log.info('Master Secret backup file doesn\'t exists. Generate new.')
            master_secret = self._generate_master_secret()
            backup_master_secret(
                master_secret, encrypt_master_secret, passphrase, salt, backup_file, time, self.rng)
            return master_secret, time

        log.info('Restore Master Secret Share from file')
        return self._restore_master_secret(
            backup_file,
            encrypt_master_secret,
            passphrase,
            salt)

    def _generate_master_secret(self):
        """Generate the M-Pin Master Secret."""
        try:
            return crypto.mpin_random_generate(self.rng)
        except crypto.CryptoError as e:
            log.error(e)
            raise SecretsError('M-Pin Master Secret Generation Failed')

    def _restore_master_secret(self, backup_file, encrypt_master_secret, passphrase, salt):
        """Restore secret from file.

        Decode secret if encrypted.
        """
        try:
            with open(backup_file) as json_file:
                backup = json.load(json_file)
        except ValueError:
            raise SecretsError('Master Secret backup file is corrupted.')

        if encrypt_master_secret:
            tag, plaintext = crypto.aes_gcm_decrypt(
                aes_key=generate_aes_key(passphrase, salt),
                iv=str(backup['IV'].decode('hex')),
                header=str(backup['startTime']),
                ciphertext=str(backup['ciphertext'].decode('hex')))

            # Check authentication tag
            if backup['tag'] != tag:
                raise SecretsError('AES-GSM Decryption Failed. Authentication tag is not correct')

            self.start_time = Time.ISOtoDateTime(str(backup['startTime']))
            master_secret = plaintext.decode('hex')
        else:
            self.start_time = Time.ISOtoDateTime(backup['startTime'])
            master_secret = backup['master_secret_hex'].decode('hex')

        return master_secret, self.start_time

    def get_server_secret(self):
        """Generate server secret."""
        try:
            return crypto.get_server_secret(self.master_secret)
        except crypto.CryptoError as e:
            log.error(e)
            raise SecretsError('Server Secret generation failed')

    def get_client_secret(self, mpin_id):
        """Generate client secret."""
        try:
            return crypto.get_client_multiple(self.master_secret, mpin_id)
        except crypto.CryptoError as e:
            log.error(e)
            raise SecretsError('Client secret generation failed')

    def get_time_permits(self, mpin_id, count):
        """Generate client time permit."""
        start_date = crypto.today()
        try:
            return dict(
                (date, crypto.get_time_permit(self.master_secret, mpin_id, date))
                for date in range(start_date, start_date + count))
        except crypto.CryptoError as e:
            log.error(e)
            raise SecretsError('M-Pin Time Permit Generation Failed')


define("certivoxServerSecret", default='dta', type=unicode)


class ServerSecret(object):

    """Server Secret."""

    server_secret = None

    def __init__(self, seed, app_id, app_key):
        """Constructor."""
        self.rng = crypto.get_random_generator(seed)
        self.app_id = app_id
        self.app_key = app_key
        self.server_secret = self._get_server_secret()

    def _get_certivox_server_secret_share_dta(self, expires):
        path = 'serverSecret'
        url_params = url_concat('{0}{1}'.format(Keys.certivoxServer(), path), {
            'app_id': self.app_id,
            'expires': expires,
            'signature': signMessage('{0}{1}{2}'.format(path, self.app_id, expires), self.app_key)
        })
        log.debug('MIRACL server secret request: {0}'.format(url_params))
        httpclient = tornado.httpclient.HTTPClient()
        try:
            response = httpclient.fetch(url_params, **fetchConfig(url_params))
        except tornado.httpclient.HTTPError as e:
            log.error(e)
            raise SecretsError('Unable to get Server Secret from the MIRACL TA server')
        httpclient.close()

        try:
            data = json.loads(response.body)
        except ValueError as e:
            log.error(e)
            raise SecretsError('Invalid response from TA server')

        if 'serverSecret' not in data:
            raise SecretsError('serverSecret not in response from TA server')

        return data["serverSecret"]

    def _get_certivox_server_secret_share_credentials(self, expires):
        if not hasattr(Keys, 'certivox_server_secret'):
            raise SecretsError(
                'MIRACL server secret share is not in the credentials.json. '
                'You can get it by: \n'
                'scripts/getServerSecretShare.py credentials.json > credentials_with_secret.json')
        return Keys.certivox_server_secret

    def _get_certivox_server_secret_share(self, expires):
        method = options.certivoxServerSecret
        methods = {
            'dta': self._get_certivox_server_secret_share_dta,
            'credentials.json': self._get_certivox_server_secret_share_credentials,
            'manual': lambda x: raw_input('MIRACL server secret share:'),
            'config': lambda x: options.certivoxServerSecret
        }
        func = methods[method if method in methods else 'config']
        certivox_server_secret_hex = func(expires)

        try:
            return certivox_server_secret_hex.decode("hex")
        except TypeError as e:
            log.error(e)
            raise SecretsError('Invalid CertiVox server secret share')

    def _get_customer_server_secret_share(self, expires):
        path = 'serverSecret'
        url_params = url_concat(
            '{0}/{1}'.format(options.DTALocalURL, path),
            {
                'app_id': self.app_id,
                'expires': expires,
                'signature': signMessage('{0}{1}{2}'.format(path, self.app_id, expires), self.app_key)
            })
        log.debug('customer server secret request: {0}'.format(url_params))

        httpclient = tornado.httpclient.HTTPClient()

        import socket
        # Make at most 30 attempts to get server secret from local TA
        for attempt in range(30):
            try:
                response = httpclient.fetch(url_params)
            except (tornado.httpclient.HTTPError, socket.error) as e:
                log.error(e)
                log.error(
                    'Unable to get Server Secret from the customer TA server. '
                    'Retying...')
                time.sleep(2)
                continue

            httpclient.close()
            break
        else:
            # Max attempts reached
            raise SecretsError(
                'Unable to get Server Secret from the customer TA server.')

        try:
            data = json.loads(response.body)
        except ValueError:
            raise SecretsError('TA server response contains invalid JSON')

        if 'serverSecret' not in data:
            raise SecretsError('serverSecret not in response from TA server')

        return data["serverSecret"].decode("hex")

    def _get_server_secret(self):
        expires = Time.syncedISO(seconds=SIGNATURE_EXPIRES_OFFSET_SECONDS)
        certivox_server_secret = self._get_certivox_server_secret_share(expires)
        customer_server_secret = self._get_customer_server_secret_share(expires)

        try:
            server_secret_hex = crypto.mpin_recombine_g2(certivox_server_secret, customer_server_secret)
        except crypto.CryptoError as e:
            log.error(e)
            raise SecretsError('M-Pin Server Secret Generation Failed')

        return server_secret_hex.decode("hex")

    def get_pass1_value(self):
        """Return pass1 value."""
        try:
            random_number = crypto.mpin_random_generate(self.rng)
        except crypto.CryptoError as e:
            log.error(e)
            raise SecretsError('Pass 1 - failed to generate Y')

        return random_number.encode('hex')

    def validate_pass2_value(self, mpin_id, u, ut, y, v):
        """Validate pass2 value.

        y - pass 1 values
        v - pass 2 value in question
        """
        date = crypto.today()
        check_dates = [date]
        if Time.syncedNow().hour < 1:
            check_dates.append(date - 1)

        for date in check_dates:
            hid, htid = crypto.mpin_server_1(mpin_id, date)
            success, _, _ = crypto.mpin_server_2(self.server_secret, v, date, hid, htid, y, u, ut)
            if success != -19:
                break

        return success
