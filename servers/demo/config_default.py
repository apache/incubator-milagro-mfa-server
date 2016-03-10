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
address = '0.0.0.0'
port = 8005

cookieSecret = '%COOKIESECRET%'

"""CDN for mpin.js"""
mpinJSURL = '%MPINJSURL%'

"""RPS discovery options"""
RPSURL = 'http://127.0.0.1:8011'
# rpsPrefix = 'rps'  # Default
clientSettingsURL = '/rps/clientSettings'
verifyIdentityURL = '/mpinActivate'

"""Key value storage options"""
# storage = 'memory'

# storage = 'redis'
# redisHost = '127.0.0.1'  # Default
# redisPort = 6379  # Default
# redisDB = 0  # Default
# redisPassword = None  # Default
# redisPrefix = 'mpin'  # Default

storage = 'json'
fileStorageLocation = './mpin_demo_storage.json'

"""Verification emails settings

If forceActivate is True the demo site will activate new users without verifying them
with email.
"""
forceActivate = True

"""Email options"""
emailSubject = 'New user activation'
emailSender = ''
smtpServer = ''
smtpPort = 25
smtpUser = ''
smtpPassword = ''
# smtpUseTLS = True

"""Mobile app"""
mobileAppPath = '%MOBILEAPPPATH%'
mobileAppFullURL = '/m'

"""Debug options"""
# logLevel = "INFO"
