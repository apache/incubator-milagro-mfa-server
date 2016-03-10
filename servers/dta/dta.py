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

from __future__ import division, absolute_import, print_function, unicode_literals

import getpass
import hashlib
import hmac
import os
import sys

import tornado.autoreload
import tornado.escape
import tornado.gen
import tornado.httpclient
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado.log import app_log as log
from tornado.options import define, options
from tornado.web import HTTPError

from mpin_utils.common import (
    detectProxy,
    getLogLevel,
    Keys,
    Seed,
    Time,
    verifySignature,
)
from mpin_utils import secrets


if os.name == "posix":
    from mpDaemon import Daemon
elif os.name == "nt":
    from mpWinService import Service as Daemon
else:
    raise Exception("Unsupported platform: {0}".format(os.name))

BASE_DIR = os.path.dirname(__file__)
CONFIG_FILE = os.path.join(BASE_DIR, "config.py")
DEFAULT_BACKUP_FILE = os.path.join(BASE_DIR, "backup.json")


# OPTIONS

# general options
define("configFile", default=os.path.join(BASE_DIR, "config.py"), type=unicode)
define("address", default="127.0.0.1", type=unicode)
define("port", default=8001, type=int)

# debugging options
define("autoReload", default=False, type=bool)
define("logLevel", default="ERROR", type=unicode)

# time synchronization options
define("timePeriod", default=86400000, type=int)
define("syncTime", default=True, type=bool)

# security options
define("credentialsFile", default=os.path.join(BASE_DIR, "credentials.json"), type=unicode)
define("EntropySources", default="dev_urandom:100", type=unicode)

# backup master secret options
define("backup", default=True, type=bool)
define("backup_file", default=DEFAULT_BACKUP_FILE, type=unicode)
define("encrypt_master_secret", default=True, type=bool)
define("passphrase", type=unicode)
define("salt", type=unicode)


# BASE HANDLERS
class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Credentials", "true")
        self.set_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.set_header("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control")

    def write_error(self, status_code, **kwargs):
        self.set_status(status_code, reason=self._reason.upper())
        self.content_type = 'application/json'
        self.write({'service_name': 'D-TA server', 'message': self._reason.upper()})

    def options(self):
        self.set_status(200, reason="OK")
        self.content_type = 'application/json'
        self.write({'service_name': 'D-TA server', 'message': "options request"})
        self.finish()
        return

    def finish(self, *args, **kwargs):
        if self._status_code == 401:
            self.set_header("WWW-Authenticate", "Authenticate")
        super(BaseHandler, self).finish(*args, **kwargs)


# HANDLERS
class ServerSecretHandler(BaseHandler):
    """
    ..  apiTextStart

    *Description*

      Retrieves the M-Pin server secret

    *URL structure*

      ``/serverSecret?app_id=<app_id>&expires=<UTC Timestamp>&signature=<signature>``

    *HTTP Request Method*

      GET

    *Parameters*

    - app_id: <identity of the Application>

    - expires: <time at which request expires>

    - signature: <signature>

    *Signature*

      The signature is generated for this message

       message = <serverSecret><app_id><expires>

    *Returns*

      Calculates the MPIN Server secret which is returned in this JSON object::
    n
        JSON response.
        {
           "message" : "OK",
           "serverSecret" : "<serverSecret>"
        }

    *Status-Codes and Response-Phrases*

      ::

        Status-Code          Response-Phrase

        200                  OK
        401                  Invalid signature
        403                  Missing argument [value]
        408                  Request expired
        500                  M-Pin Server Secret Generation

    .. apiTextEnd

    """
    def get(self):
        # Remote request information
        if 'User-Agent' in self.request.headers.keys():
            UA = self.request.headers['User-Agent']
        else:
            UA = 'unknown'
        request_info = '%s %s %s %s ' % (self.request.method, self.request.path, self.request.remote_ip, UA)

        # Get arguments
        try:
            app_id = str(self.get_argument('app_id'))
            expires = self.get_argument('expires')
            signature = self.get_argument('signature')
        except tornado.web.MissingArgumentError as ex:
            reason = ex.log_message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'message': reason})
            self.finish()
            return
        request_info = request_info + app_id

        # Get path used for signature
        path = self.request.path
        path = path.replace("/", "")

        # Check signature is valid and that timestamp has not expired
        M = str("%s%s%s" % (path, Keys.app_id, expires))
        valid, reason, code = verifySignature(M, signature, Keys.app_key, expires)
        if not valid:
            return_data = {
                'code': code,
                'message': reason
            }
            log.error("%s %s" % (request_info, reason))
            self.set_status(status_code=code, reason=reason)
            self.content_type = 'application/json'
            self.write(return_data)
            self.finish()
            return

        try:
            server_secret_hex = self.application.master_secret.get_server_secret()
        except secrets.SecretsError as e:
            log.error('M-Pin Server Secret Generation Failed: {0}. Request info: {1}'.format(e, request_info))
            return_data = {
                'errorCode': e.message,
                'reason': 'M-Pin Server Secret Generation Failed',
            }
            self.set_status(500, reason=reason)
            self.content_type = 'application/json'
            self.write(return_data)
            self.finish()
            return

        # Hash server secret share
        server_secret = server_secret_hex.decode("hex")
        hash_server_secret_hex = hashlib.sha256(server_secret).hexdigest()
        log.info("%s hash_server_secret_hex: %s" % (request_info, hash_server_secret_hex))

        # Returned data
        reason = "OK"
        self.set_status(200, reason=reason)
        self.content_type = 'application/json'
        return_data = {
            'serverSecret': server_secret_hex,
            'startTime': Time.DateTimeToISO(self.application.master_secret.start_time),
            'message': reason
        }
        self.write(return_data)
        log.debug("%s %s" % (request_info, return_data))
        self.finish()
        return


class ClientSecretHandler(BaseHandler):
    """
    ..  apiTextStart

    *Description*

      Retrieves the M-Pin client secret

    *URL structure*

      ``/clientSecret?app_id=<app_id>&expires=<UTC Timestamp>&hash_mpin_id=<hash_mpin_id>&signature=<signature>&mobile=<0||1>``

    *HTTP Request Method*

      GET

    *Parameters*


    - app_id: identity of the Application

    - hash_mpin_id:  hex encoded hash of the M-Pin identity for which client secret is requested

    - expires: time at which request expires

    - signature: signature

    - mobile: 1 means mobile request || 0 means desktop request

    *Signature*

      The signature is generated for this message using a hmac

      message = <clientSecret><app_id><hash_mpin_id><expires>

    *Returns*

      Calculates the MPIN Client secret which is returned in this JSON object::

        JSON response.
        {
           "message" : "OK",
           "clientSecret" : "<clientSecret>"
        }

    *Status-Codes and Response-Phrases*

      ::

        Status-Code          Response-Phrase

        200                  OK
        401                  Invalid signature
        403                  Missing argument [value]
        403                  Invalid data received. Hex object could be decoded
        403                  Invalid data received. hash_mpin_id null
        403                  Invalid data received. hash_mpin_id should be 64 bytes
        408                  Request expired
        500                  M-Pin Client Secret Generation Failed

    .. apiTextEnd

    """
    def get(self):
        # Remote request information
        if 'User-Agent' in self.request.headers.keys():
            UA = self.request.headers['User-Agent']
        else:
            UA = 'unknown'
        request_info = '%s %s %s %s ' % (self.request.method, self.request.path, self.request.remote_ip, UA)

        # Get arguments
        try:
            app_id = str(self.get_argument('app_id'))
            expires = self.get_argument('expires')
            signature = self.get_argument('signature')
            hash_mpin_id_hex = self.get_argument('hash_mpin_id')
            hash_mpin_id = hash_mpin_id_hex.decode("hex")
            hash_user_id = self.get_argument('hash_user_id')
        except tornado.web.MissingArgumentError as ex:
            reason = ex.log_message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'message': reason})
            self.finish()
            return
        except TypeError as ex:
            reason = "Invalid data received. Hex object could be decoded"
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'message': reason})
            self.finish()
            return
        if len(hash_mpin_id_hex) != 64:
            reason = "Invalid data received. hash_mpin_id should be 64 bytes"
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'message': reason})
            self.finish()
            return
        request_info = request_info + app_id + " " + hash_mpin_id_hex

        # Get path used for signature
        path = self.request.path
        path = path.replace("/", "")

        # Check signature is valid and that timestamp has not expired
        M = str("%s%s%s%s%s" % (path, Keys.app_id, hash_mpin_id_hex, hash_user_id, expires))
        valid, reason, code = verifySignature(M, signature, Keys.app_key, expires)
        if not valid:
            return_data = {
                'code': code,
                'message': reason
            }
            log.error("%s %s" % (request_info, reason))
            self.set_status(status_code=code, reason=reason)
            self.content_type = 'application/json'
            self.write(return_data)
            self.finish()
            return

        try:
            client_secret_hex = self.application.master_secret.get_client_secret(hash_mpin_id)
        except secrets.SecretsError as e:
            return_data = {
                'errorCode': e.message,
                'message': 'M-Pin Client Secret Generation Failed'
            }
            log.error("%s %s" % (request_info, reason))
            self.set_status(500, reason=reason)
            self.content_type = 'application/json'
            self.write(return_data)
            self.finish()
            return
        # Hash client secret share
        client_secret = client_secret_hex.decode("hex")
        hash_client_secret_hex = hashlib.sha256(client_secret).hexdigest()
        log.info("%s hash_client_secret_hex: %s" % (request_info, hash_client_secret_hex))

        reason = "OK"
        self.set_status(200, reason=reason)
        self.content_type = 'application/json'
        return_data = {
            'clientSecret': client_secret_hex,
            'message': reason
        }
        self.write(return_data)
        log.debug("%s %s" % (request_info, return_data))
        self.finish()
        return


class TimePermitsHandler(BaseHandler):

    def get_hash_mpin_id_hex(self):
        try:
            hash_mpin_id_hex = self.get_argument('hash_mpin_id')
        except tornado.web.MissingArgumentError as e:
            log.debug(e)
            raise HTTPError(403, e.log_message)

        if len(hash_mpin_id_hex) != 64:
            reason = "Invalid data received. hash_mpin_id should be 64 bytes"
            log.debug(reason)
            raise HTTPError(403, reason)

        return hash_mpin_id_hex

    def get_hash_mpin_id(self, hash_mpin_id_hex):
        hash_mpin_id_hex = self.get_hash_mpin_id_hex()
        try:
            return hash_mpin_id_hex.decode("hex")
        except TypeError:
            reason = "Invalid data received. Hex object could be decoded"
            log.debug(reason)
            raise HTTPError(403, reason)

    def get_signature(self):
        try:
            return self.get_argument('signature')
        except tornado.web.MissingArgumentError as e:
            raise HTTPError(403, e.log_message)

    def get_count(self):
        try:
            count = self.get_argument('count')
        except tornado.web.MissingArgumentError as e:
            raise HTTPError(403, e.log_message)

        try:
            count = int(count)
        except ValueError:
            raise HTTPError(403, 'Count invalid format integer')

        return count

    def verify_signature(self, signature, hash_mpin_id_hex):
        hmacExpected = hmac.new(Keys.app_key, hash_mpin_id_hex.encode('utf-8'), hashlib.sha256).hexdigest()
        hmac1 = hmac.new(Keys.app_key, signature, hashlib.sha256).hexdigest()
        hmac2 = hmac.new(Keys.app_key, hmacExpected, hashlib.sha256).hexdigest()
        return hmac1 == hmac2

    def get_timepermits(self, hash_mpin_id, count):
        try:
            time_permits = self.application.master_secret.get_time_permits(
                hash_mpin_id, count=count)
        except secrets.SecretsError as e:
            raise HTTPError(500, e.message)

        return time_permits

    def get(self):
        hash_mpin_id_hex = self.get_hash_mpin_id_hex()
        hash_mpin_id = self.get_hash_mpin_id(hash_mpin_id_hex)
        signature = self.get_signature()
        count = self.get_count()

        if not self.verify_signature(signature, hash_mpin_id_hex):
            reason = "Invalid signature"
            log.debug(reason)
            raise HTTPError(401, reason)

        self.finish({
            'timePermits': self.get_timepermits(hash_mpin_id, count),
            'message': 'OK'
        })


class TimePermitHandler(TimePermitsHandler):

    """Kept for backwards compatibility."""

    def get_timepermit(self, hash_mpin_id):
        return self.get_timepermits(hash_mpin_id, 1).values()[0]

    def get(self):
        hash_mpin_id_hex = self.get_hash_mpin_id_hex()
        hash_mpin_id = self.get_hash_mpin_id(hash_mpin_id_hex)
        signature = self.get_signature()

        if not self.verify_signature(signature, hash_mpin_id_hex):
            reason = "Invalid signature"
            log.debug(reason)
            raise HTTPError(401, reason)

        self.finish({
            'timePermit': self.get_timepermit(hash_mpin_id),
            'message': 'OK'
        })


class StatusHandler(BaseHandler):
    """
    ..  apiTextStart

    *Description*

      Retrieves status of the D-TA Proxy.

    *URL structure*

      ``/status``

    *HTTP Request Method*

      GET

    *Returns*

      JSON response::

        {
           'message' : 'OK',
           'startTime': <DateTime>
           'service_name': 'D-TA server'
        }

    *Status-Codes and Response-Phrases*

      ::

        Status-Code          Response-Phrase

        200                  OK

    ..  apiTextEnd
    """

    def get(self):
        reason = "OK"
        self.set_status(200, reason=reason)
        start_time_str = Time.DateTimeToISO(self.application.master_secret.start_time),
        self.write({'startTime': start_time_str, 'service_name': 'D-TA server', 'message': reason})
        return


class DefaultHandler(BaseHandler):
    def get(self, input):
        reason = "NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'service_name': 'D-TA server', 'message': reason})
        return

    def post(self, input):
        reason = "URI NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'service_name': 'D-TA server', 'message': reason})
        return

    def put(self, input):
        reason = "URI NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'service_name': 'D-TA server', 'message': reason})
        return

    def delete(self, input):
        reason = "URI NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'service_name': 'D-TA server', 'message': reason})
        return


# MAIN
class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/clientSecret", ClientSecretHandler),
            (r"/serverSecret", ServerSecretHandler),
            (r"/timePermit", TimePermitHandler),
            (r"/timePermits", TimePermitsHandler),
            (r"/status", StatusHandler),
            (r"/(.*)", DefaultHandler),
        ]
        settings = dict(
            xsrf_cookies=False
        )
        super(Application, self).__init__(handlers, **settings)

        Seed.getSeed(options.EntropySources)  # Get seed value for random number generator
        self.master_secret = secrets.MasterSecret(
            passphrase=options.passphrase,
            salt=options.salt,
            seed=Seed.seedValue,
            backup_file=options.backup_file,
            encrypt_master_secret=options.encrypt_master_secret,
            time=Time.syncedNow())


def main():
    options.parse_command_line()

    if os.path.exists(options.configFile):
        try:
            options.parse_config_file(options.configFile)
            options.parse_command_line()
        except Exception, E:
            print("Invalid config file {0}".format(options.configFile))
            print(E)
            sys.exit(1)

    # Set Log level
    log.setLevel(getLogLevel(options.logLevel))

    detectProxy()

    # Load the credentials from file
    log.info("Loading credentials")
    try:
        credentialsFile = options.credentialsFile
        Keys.loadFromFile(credentialsFile)
    except Exception as E:
        log.error("Error opening the credentials file: {0}".format(credentialsFile))
        log.error(E)
        sys.exit(1)

    # TMP fix for 'ValueError: I/O operation on closed epoll fd'
    # Fixed in Tornado 4.2
    tornado.ioloop.IOLoop.instance()

    # Sync time to CertiVox time server
    if options.syncTime:
        Time.getTime(wait=True)

    if options.backup and options.encrypt_master_secret and not options.passphrase:
        options.passphrase = getpass.getpass("Please enter passphrase:")

    http_server = Application()
    http_server.listen(options.port, options.address, xheaders=True)
    io_loop = tornado.ioloop.IOLoop.instance()

    if options.autoReload:
        log.debug("Starting autoreloader")
        tornado.autoreload.watch(CONFIG_FILE)
        tornado.autoreload.start(io_loop)

    if options.syncTime and (options.timePeriod > 0):
        scheduler = tornado.ioloop.PeriodicCallback(Time.getTime, options.timePeriod, io_loop=io_loop)
        scheduler.start()

    log.info("Server started. Listening on {0}:{1}".format(options.address, options.port))
    io_loop.start()


class ServiceDaemon(Daemon):
    def run(self):
        main()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("start", "stop"):
        action = sys.argv.pop(1)
        logFile = os.path.join(BASE_DIR, "dta.log")
        pidFile = os.path.join(BASE_DIR, "dta.pid")

        daemon = ServiceDaemon(pidfile=pidFile, stdout=logFile, stderr=logFile)
        if action == "start":
            log.info("Starting as daemon. Log file: {0}".format(logFile))
            daemon.start()
        elif action == "stop":
            log.info("Stopping daemon...")
            daemon.stop()
            sys.exit()
    else:
        try:
            main()
        except Exception as e:
            log.error(e)
            sys.exit(1)
