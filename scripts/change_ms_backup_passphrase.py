#!/usr/bin/env python
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

"""Decrypt master secret backup and crypt it back with new passphrase."""
from __future__ import division, absolute_import, print_function, unicode_literals

import os
from datetime import datetime
from getpass import getpass

from mpin_utils import secrets
from mpin_utils.common import Seed

DEFAULT_BACKUP_FILE = './backup.json'
DEFAULT_ENTROPY_SOURCES = 'dev_urandom:100'


def main():
    """Main function."""
    while True:
        backup_file = raw_input('Path to M-Pin master secret backup file (Default: {0}): '.format(DEFAULT_BACKUP_FILE)) or DEFAULT_BACKUP_FILE
        if not os.path.exists(backup_file):
            print('No such file {0}'.format(backup_file))
        else:
            break

    old_passphrase = getpass('Passphrase for {0}: '.format(backup_file))
    salt = raw_input('SALT used for old encryption:') or ''
    entropy_sources = raw_input('Entropy sources (Default: {0}): '.format(DEFAULT_ENTROPY_SOURCES)) or DEFAULT_ENTROPY_SOURCES

    Seed.getSeed(entropy_sources)
    seed = Seed.seedValue

    secrets_obj = secrets.Secrets(
        old_passphrase, salt, seed, datetime.now(), backup_file, True)

    while True:
        new_passphrase1 = getpass("Please enter passphrase: ")
        new_passphrase2 = getpass("Please enter passphrase (again): ")

        if new_passphrase1 == new_passphrase2:
            new_passphrase = new_passphrase1
            break
        else:
            print('Passphrases don\'t match')

    secrets.backup_master_secret(
        secrets_obj.master_secret, True, new_passphrase, salt, backup_file,
        secrets_obj.start_time, secrets_obj.rng)

if __name__ == "__main__":
    main()
