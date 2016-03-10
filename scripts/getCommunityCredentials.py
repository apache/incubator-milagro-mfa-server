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

import datetime
import hashlib
import hmac
import json
import os
import sys
import urllib2

KEYS_ENDPOINT = "https://register.certivox.net/api/v3/platform/core"
INSTALLER_KEY = "b4e62b5ae100dd51dfc0d910579b3311"
DEFAULT_INSTALL_PATH = "/opt/mpin"
INSTALLATION_TYPE = "mpincore"


class Console(object):
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CLEAR = '\033[0m'

    @staticmethod
    def initConsole():
        # Check for console colors support
        if not sys.stdout.isatty():
            Console.BLUE, Console.GREEN, Console.YELLOW, Console.RED, Console.CLEAR = ["" for _ in range(5)]

    @staticmethod
    def out(rawtext):
        sys.stdout.write(rawtext)
        sys.stdout.flush()

    @staticmethod
    def text(text, newLine=True):
        sys.stdout.write("{0}{1}{2}".format(Console.CLEAR, text, newLine and "\n" or " "))
        sys.stdout.flush()

    @staticmethod
    def info(text, newLine=True):
        sys.stdout.write("{0}{1}{2}{3}".format(Console.GREEN, text, Console.CLEAR, newLine and "\n" or " "))
        sys.stdout.flush()

    @staticmethod
    def blue(text, newLine=True):
        sys.stdout.write("{0}{1}{2}{3}".format(Console.BLUE, text, Console.CLEAR, newLine and "\n" or " "))
        sys.stdout.flush()

    @staticmethod
    def error(text="ERROR", newLine=True):
        sys.stdout.write("{0}{1}{2}{3}".format(Console.RED, text, Console.CLEAR, newLine and "\n" or " "))
        sys.stdout.flush()

    @staticmethod
    def fatal(text, prevLineStrip=False):
        if prevLineStrip:
            Console.error()
        Console.error("*** {0}\n".format(text))
        sys.exit(1)

    @staticmethod
    def done(text="Done", newLine=True):
        sys.stdout.write("{0}{1}{2}".format(Console.CLEAR, text, newLine and "\n" or " "))
        sys.stdout.flush()

    @staticmethod
    def ok(text="Ok", newLine=True):
        Console.done(text)
        sys.stdout.flush()

    @staticmethod
    def getInput(text, validateFunc=None, errorMessage=None):
        while True:
            try:
                r_input = raw_input
            except NameError:
                r_input = input

            try:
                res = r_input("{0}{1}: ".format(Console.CLEAR, text))
            except KeyboardInterrupt:
                Console.fatal("Installation interrupted.")

            if not validateFunc:
                break
            else:
                v = validateFunc(res)
                if v:
                    break
                else:
                    if errorMessage:
                        Console.error(errorMessage)

        return res


def signMessage(message, key):
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()


def requestFreeKeys(user_contact):
    method = "POST"
    path = "getCommunityCredentials"
    installation_type = INSTALLATION_TYPE
    timestamp = datetime.datetime.utcnow().isoformat()
    user_contact_hex = user_contact.encode("hex")
    M = "{0}{1}{2}{3}{4}".format(method, path, installation_type, timestamp, user_contact_hex)
    signature = signMessage(M, INSTALLER_KEY)

    params = {
        "method": method,
        "path": path,
        "installation_type": installation_type,
        "timestamp": timestamp,
        "user_contact_hex": user_contact_hex,
        "signature": signature
    }

    try:
        req = urllib2.Request(KEYS_ENDPOINT, data=json.dumps(params), headers={"Content-Type": "application/json"})
        resp = urllib2.urlopen(req)
        return True, json.dumps(json.loads(resp.read()), indent=4)
    except urllib2.URLError, e:
        try:
            code = e.code
        except:
            code = ""
        return False, "{0} {1}".format(code, e.reason)


def getFreeKeys(installPath):

    Console.text(
        'You can enter an email address or a Twitter account to be contacted on by our support team for '
        'full info on out to get the most value from M-Pin Core. ',
        False
    )
    Console.text('To skip this step just hit enter, you can still contact us on support@miracl.com or on Twitter on @miraclhq\n')
    user_contact = Console.getInput('Your email or Twitter account')

    Console.text("\nGetting Community D-TA keys...", False)

    ok, result = requestFreeKeys(user_contact)

    if ok:
        credentialsFile = os.path.join(installPath, "credentials.json")
        try:
            open(credentialsFile, "w").write(result)
            Console.info("Done\n")
        except Exception, e:
            Console.error("Fail")
            Console.error("Unable to write Community D-TA credentials file: {0}\n".format(e))
            Console.text("Your credentials.json:")
            Console.text(result)

    else:
        Console.error("Fail")
        Console.error("Unable to get Community D-TA keys: {0}".format(result))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        installPath = sys.argv[1]
    else:
        installPath = DEFAULT_INSTALL_PATH

    getFreeKeys(installPath)
