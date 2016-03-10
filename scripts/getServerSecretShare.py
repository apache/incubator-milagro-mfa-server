#! /usr/bin/env python
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

from __future__ import unicode_literals

import datetime
import hashlib
import hmac
import json
import sys
import traceback
import urllib
import urllib2

SIGNATURE_EXPIRES_SECONDS = 60


class ScriptException(Exception):
    pass


def sign_message(message, key):
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()


def get_arguments():
    if len(sys.argv) < 2:
        raise ScriptException('credentials.json required')

    if len(sys.argv) > 2:
        raise ScriptException('Unexpected number of arguments')

    return sys.argv[1]


def get_credentials(credentials_json):
    """ Parses the content of the file.

    Will raise exception if any of the required keys are missing.
    """
    try:
        with open(credentials_json, 'r') as credentials_file:
            credentials = json.loads(credentials_file.read())
    except IOError:
        raise ScriptException('Invalid filename')
    except ValueError:
        print credentials_file.read()
        raise ScriptException('Invalid json (invalid formating)')

    for key in ['app_id', 'app_key', 'api_url']:
        if key not in credentials:
            raise ScriptException('Invalid json ({} key missing)'.format(key))

    return credentials


def get_expiration_time():
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=SIGNATURE_EXPIRES_SECONDS)
    expires_str = expires.isoformat().split(".")[0] + "Z"
    return expires_str


def get_server_secret(credentials, expires):
    """ Fetch server secret from CertiVox server """
    path = 'serverSecret'
    params = urllib.urlencode({
        'app_id': credentials['app_id'],
        'expires': expires,
        'signature': sign_message(
            '{}{}{}'.format(path, credentials['app_id'], expires),
            str(credentials['app_key'])
        )
    })

    try:
        response = urllib2.urlopen('{api_url}{end_point}?{params}'.format(
            api_url=credentials['api_url'],
            end_point=path,
            params=params,
        ))
    except urllib2.HTTPError as e:
        if e.code == 408:
            print "Make sure your time it correct!"
        raise ScriptException('Response code: {} - {}'.format(e.code, e.read()))

    data = json.loads(response.read())
    return data['serverSecret']


def main():
    credentials_filename = get_arguments()
    credentials = get_credentials(credentials_filename)

    # Make a request for CertiVox server secret share
    server_secret = get_server_secret(credentials, get_expiration_time())

    # Add to initial credential json and print to stdout
    credentials['certivox_server_secret'] = server_secret
    print json.dumps(credentials, indent=2)


if __name__ == '__main__':
    try:
        main()
    except ScriptException as e:
        print(e)
    except KeyboardInterrupt:
        print "Shutdown requested...exiting"
    except Exception:
        traceback.print_exc(file=sys.stdout)
    sys.exit(0)
