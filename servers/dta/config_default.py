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

from __future__ import unicode_literals

"""HTTP server settings"""
address = "127.0.0.1"
port = 8001

"""Time synchronization

To be able to perform time based verification, by default D-TA syncs its time
with MIRACL servers. If you set it to False, you should still sync the server
using an accurate NTP time server!
"""
# syncTime = False

"""The location of your keys file (relative to mpin-backend/servers/dta)."""
credentialsFile = '%CREDENTIALSFILE%'

"""Entropy sources

D-TA supports multiple ways to gather entropy random, urandom, certivox or
combination of those.
"""
# EntropySources = 'dev_urandom:100'  # Default
# EntropySources = 'certivox:100'
# EntropySources = 'dev_urandom:60,certivox:40'

"""Backup master secret

D-TA supports storing the master secret in a file rather than generating it every
time on startup. It is enabled by default, set to False to disable. Master secret
will be encrypted by default unless disabled by settingencrypt_master_secret to
False. Master secret will be encoded with passphrase and salt to be provided
- salt in the config file
- passphrase - supplied on startup or in the config (not encouraged)

Passphrase can be changed by running the service with changePassphrase option.

To change the location of the backup file change backup_file option (relative to
mpin-backend/servers/dta).
"""
# backup = False
backup_file = '%BACKUP_FILE%'
# encrypt_master_secret = False
passphrase = '%PASSPHRASE%'
salt = '%SALT%'

"""Debug options"""
# logLevel = "INFO"
