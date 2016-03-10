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
address = '127.0.0.1'
port = 8011

"""Set Access-Control-Allow-Origin header"""
# allowOrigin = ['*']

"""Time synchronization

To be able to perform time based verification, by default RPS syncs its time
with MIRACL servers. If you set it to False, you should still sync the server
using an accurate NTP time server!
"""
# syncTime = False

"""
Dynamic options url

Location to be queried for dynamically (runtime) changeable options.
'None' mean dynamic options are disabled and it is default value.
"""
# dynamicOptionsURL = None  # Default

"""The location of your keys file (relative to mpin-backend/servers/dta)."""
credentialsFile = '%CREDENTIALSFILE%'

"""Entropy sources

D-TA supports multiple ways to gather entropy random, urandom, certivox or
combination of those.
"""
# EntropySources = 'dev_urandom:100'  # Default
# EntropySources = 'certivox:100'
# EntropySources = 'dev_urandom:60,certivox:40'

"""MIRACL server secret share acquisition

- dta - get server secret from MIRACL dta automatically on start
- credentials.json - get server secret from credentials.json (key: certivox_server_secret)
- manual - service will prompt for it
- the secret itself

You can get your MIRACL server secret by:
    ./scripts/getServerSecretShare.py credentials.json
which will output your credentials json including certivox_server_secret.
NOTE: Don't pipe it directly to the same file - you'll lose your original
      credentials file.
Alternatively you can copy only your certivox_server_secret value and supply it
either manually or via config.py setting the certivoxServerSecret to the
corresponding value.
"""
# certivoxServerSecret = 'dta'  # Default

"""Local DTA address."""
DTALocalURL = 'http://127.0.0.1:8001'

"""Access number options

- enable access number
- accessNumberExpireSeconds - The default time client will show the access number
- accessNumberExtendValiditySeconds - Validity of the access number (on top of accessNumberExpireSeconds)
- accessNumberUseCheckSum - Should access number have checksum
"""
# requestOTP = True
# accessNumberExpireSeconds = 60  # Default
# accessNumberExtendValiditySeconds = 5  # Default
# accessNumberUseCheckSum = True  # Default

"""Authentication options

- waitForLoginResult -For the mobile flow. Wait the browser login before showing the Done/Logout button.
"""
waitForLoginResult = True
# VerifyUserExpireSeconds = 3600  # Default
# maxInvalidLoginAttempts = 3  # Default
# cacheTimePermits = True   #Default

"""RPA options

- RPAPermitUserURL - RPA Revocation endpoint
- RegisterForwardUserHeaders - Coma separated list of headers
    - '' - do not forward headers
    - * - forward all headers
- LogoutURL - RPA Logout url. For logout using the mobile client.
"""
RPAVerifyUserURL = 'http://127.0.0.1:8005/mpinVerify'
# RPAPermitUserURL = 'http://127.0.0.1:8005/mpinPermitUser'
RPAAuthenticateUserURL = '/mpinAuthenticate'
RegisterForwardUserHeaders = ''
LogoutURL = '/logout'

"""PIN pad client options"""
# rpsBaseURL = ''
# rpsPrefix = 'rps'  # Default
# setDeviceName = True

"""Key value storage options"""
storage = 'memory'

# storage = 'redis'
# redisHost = '127.0.0.1'  # Default
# redisPort = 6379  # Default
# redisDB = 0  # Default
# redisPassword = None  # Default
# redisPrefix = 'mpin'  # Default

# storage = 'json'
# fileStorageLocation = './mpin_rps_storage.json'

"""Debug options"""
# logLevel = "INFO"

"""Use NFC flag for mobile clients"""
useNFC = False
