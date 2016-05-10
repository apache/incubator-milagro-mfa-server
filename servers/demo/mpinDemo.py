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

import datetime
import json
import os
import sys
import time
import uuid
from urlparse import urlparse

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

import mailer
from mpin_utils.common import detectProxy, getLogLevel, Time
from storage import get_storage_cls

if os.name == "posix":
    from mpDaemon import Daemon
elif os.name == "nt":
    from mpWinService import Service as Daemon
else:
    raise Exception("Unsupported platform: {0}".format(os.name))

BASE_DIR = os.path.dirname(__file__)
CONFIG_FILE = os.path.join(BASE_DIR, "config.py")


# OPTIONS

# general options
define("configFile", default=os.path.join(BASE_DIR, "config.py"), type=unicode)
define("address", default="127.0.0.1", type=unicode)
define("port", default=8005, type=int)
define("cookieSecret", type=unicode)
define("resourcesBasePath", default=BASE_DIR, type=unicode)
define("mpinJSURL", default="", type=unicode)

# debugging options
define("autoReload", default=False, type=bool)
define("logLevel", default="ERROR", type=unicode)
define("forceActivate", default=False, type=bool)

# RPS service discovery options
define("RPSURL", default="", type=unicode)
define("rpsPrefix", default="rps", type=unicode)
define("clientSettingsURL", default="", type=unicode)
define("verifyIdentityURL", default="", type=unicode)

# authentication options
define("requestOTP", default=False, type=bool)

# email options
define("emailSubject", type=unicode)
define("emailSender", type=unicode)
define("smtpServer", type=unicode)
define("smtpPort", default=25, type=int)
define("smtpUser", type=unicode)
define("smtpPassword", type=unicode)
define("smtpUseTLS", default=False, type=bool)

# mobile
define("mobileOnly", default=False, type=bool)
define("mobileSupport", default=True, type=bool)
define("mobileAppPath", default="", type=unicode)
define("mobileAppFullURL", default="", type=unicode)

define("mobileUseNative", default=False, type=bool)
define("mobileConfigURL", default=None, type=unicode)


# UTILITIES
class MobileLoginHandler(object):
    def __init__(self):
        self.waiters = dict()

    def waitForLogin(self, callback, sessionId, logout=False):
        sid = logout and ("logout;%s" % sessionId) or sessionId
        log.debug("Adding callback for session {0}".format(sid))
        self.waiters[sid] = callback

    def cancelWait(self, sessionId, logout=False):
        sid = logout and ("logout;%s" % sessionId) or sessionId
        if self.waiters.get(sid):
            del self.waiters[sid]

    def userLogged(self, sessionId, logout=False):
        sid = logout and ("logout;%s" % sessionId) or sessionId
        log.debug("WAITING CALLBACK FOR: {0}".format(sid))

        callback = self.waiters.get(sid)
        if callback:
            callback()
            if self.waiters.get(sid):
                del self.waiters[sid]
            return True
        else:
            log.debug("No Callback!")

            return False
mobileLoginHandler = MobileLoginHandler()


def generateSessionID():
    return uuid.uuid4().hex + uuid.uuid1().hex


# BASE HANDLERS
class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Credentials", "true")
        self.set_header("Access-Control-Allow-Methods", "GET,POST,HEAD,OPTIONS")
        self.set_header("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, Pragma, Expires, WWW-Authenticate")
        # self.set_header("Connection", "keep-alive")

        self.set_header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
        self.set_header("Pragma", "no-cache")
        self.set_header("Expires", "Sat, 26 Jul 1997 05:00:00 GMT")

    def prepare(self):
        self.sessionId = self.get_secure_cookie("mpindemo_session")

        if not self.sessionId:
            self.sessionId = generateSessionID()
            log.debug("Generated new sessionId: {0}".format(self.sessionId))
            self.set_secure_cookie("mpindemo_session", self.sessionId)
            self.loggedUser = ""
        else:
            item = self.storage.find(key="s;{0}".format(self.sessionId))
            self.loggedUser = item.value if item else None

    def get_flash(self):
        flash = self.get_secure_cookie("flash")
        if flash:
            self.clear_cookie("flash")
        return flash

    def set_flash(self, message):
        self.set_secure_cookie("flash", message)

    @property
    def storage(self):
        return self.application.storage

    def finish(self, *args, **kwargs):
        if self._status_code == 401:
            log.error('asdasdasd')
            self.set_header("WWW-Authenticate", "Authenticate")
        super(BaseHandler, self).finish(*args, **kwargs)


# APPLICATION HANDLERS
class RPSRedirectHandler(BaseHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'PUT', 'OPTIONS']

    @tornado.web.asynchronous
    @tornado.gen.engine
    def _processRequest(self, path):

        url = "{0}/{1}".format(options.RPSURL.rstrip("/"), self.request.uri.strip("/"))
        method = self.request.method
        headers = self.request.headers
        data = self.request.body

        if (not data) and (method in ["GET", "OPTIONS"]):
            data = None

        client = tornado.httpclient.AsyncHTTPClient()

        response = yield tornado.gen.Task(client.fetch, url, method=method, headers=headers, body=data)

        for h in response.headers:
            hV = response.headers.get(h)
            if hV:
                self.set_header(h, hV)

        if (response.error):
            if response.code > 500:
                errorCode = 500
            else:
                errorCode = response.code
            self.set_status(errorCode)
        else:
            self.set_status(response.code)

        if response.body:
            self.write(response.body)
        self.finish()

    def get(self, path):
        return self._processRequest(path)

    def post(self, path):
        return self._processRequest(path)

    def put(self, path):
        return self._processRequest(path)

    def options(self, path):
        return self._processRequest(path)


class IndexHandler(BaseHandler):

    def get(self):
        mobileAppURL = options.mobileAppFullURL

        if not mobileAppURL.startswith("http"):
            pr = urlparse(self.request.full_url())
            mobileAppURL = "{0}://{1}{2}".format(pr.scheme, pr.netloc, mobileAppURL or "/m")

        params = {
            "clientSettingsURL": options.clientSettingsURL,
            "mobileAppFullURL": mobileAppURL,
            "mpinJSURL": options.mpinJSURL,
            "logoutWaitURL": "/logoutWait",
            "user": self.loggedUser,
            "mobileOnly": options.mobileOnly and "true" or "false",
            "mobileSupport": options.mobileSupport and "true" or "false",
            "mobileUseNative": options.mobileUseNative,
            "mobileConfigURL": options.mobileConfigURL
            # "emailCheckRegex": "[0-9a-zA-Z]+"
        }

        templateName = self.request.path == "/login" and "login.html" or "index.html"

        self.render(templateName, flash=self.get_flash(), **params)


class VerifyUserHandler(BaseHandler):

    def _generateValidationURL(self, base_url, identity, signature, expires):
        return "{0}?i={1}&e={2}&s={3}".format(base_url, identity, expires, signature)

    def post(self):
        self.content_type = 'application/json'

        try:
            data = json.loads(self.request.body)
            identity = data["mpinId"]
            userid = data["userId"]
            expireTime = data["expireTime"]
            mobile = data["mobile"]

            activateKey = data.get("activateKey", "")
            activationCode = int(data.get("activationCode", 0))

        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return

        userId = data.get("userId")
        if not userId:
            log.error("Missing userId")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID USER ID")
            self.finish()
            return

        deviceName = mobile and "Mobile" or "PC"

        if options.forceActivate:
            log.warning("forceActivate option set! User activated without verification!")
        else:
            ## for ActivateKey
            if ((type(activateKey) is str) or (type(activateKey) is unicode)) and (activateKey != ''):
                if options.verifyIdentityURL.startswith("/"):  # relative path
                    base_url = "{0}/{1}".format(
                        self.request.headers.get("RPS-BASE-URL").rstrip("/"),
                        options.verifyIdentityURL.lstrip("/")
                    )
                else:
                    base_url = options.verifyIdentityURL

                validateURL = self._generateValidationURL(base_url, identity, activateKey, expireTime)
                log.info("Sending activation email for user {0}: {1}".format(userid.encode("utf-8"), validateURL))

                mailer.sendActivationEmail(userid.encode("utf-8"), options.emailSubject, deviceName, validateURL, options.smtpUser, options.smtpPassword)

            ## for ActivationCode
            if (type(activationCode) is int) and (activationCode != 0):
                log.info("Sending activation email for user {0}, activationCode: {1}".format(userid.encode("utf-8"), activationCode))

                mailer.sendEMpinActivationEmail(userid.encode("utf-8"), options.emailSubject, deviceName, activationCode, options.smtpUser, options.smtpPassword)

            log.warning("Sending Mail!")

        responseData = {
            "forceActivate": options.forceActivate
        }
        self.write(json.dumps(responseData))

        self.set_status(200)
        self.finish()


class mpinPermitUserHandler(BaseHandler):

    def get(self):

        # The revocation handler
        # When the RPS option RPAPermitUserURL is set
        # It will make a request for validating the identity
        # Before giving the time permit share to the client

        self.content_type = 'application/json'

        # If you return 403 it will show Unauthoirized message inside the PinPad
        # self.set_status(403)

        self.set_status(200)  # We give permissions to everyone
        self.finish()


class mpinActivateHandler(BaseHandler):
    def _verifySignature(self):
        identity = self.get_argument("i", default="")
        expires = self.get_argument("e", default="")
        signature = self.get_argument("s", default="")

        log.debug("/mpinActivate request for identity: {0}".format(identity))

        try:
            data = json.loads(identity.decode("hex"))
            userid = data["userID"]
            issued = data["issued"]
            sIssued = Time.DateTimetoHuman(Time.ISOtoDateTime(issued))

            mobile = int(data.get("mobile") or 0)

        except Exception as E:
            log.error("Error parsing the verification email: {0}".format(E))
            userid, issued, sIssued = None, None, None

        if userid:
            if expires < datetime.datetime.utcnow().isoformat(b"T").split(".")[0] + "Z":
                isValid = False
                info = "Link expired"
            else:
                isValid = True
                info = ""

            deviceName = mobile and "Mobile" or "PC"

        else:
            log.error("/mpinActivate: Invalid IDENTITY: {0}".format(identity))
            isValid, info = False, "Invalid identity"
            deviceName, issued = "", ""

        params = {
            "isValid": isValid,
            "identity": identity,
            "errorMessage": info,
            "userid": userid,
            "issued": issued,
            "humanIssued": sIssued,
            "activated": False,
            "deviceName": deviceName,
            "activateKey": signature
        }

        return params

    def get(self):
        params = self._verifySignature()
        self.render("activate.html", **params)

    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        params = self._verifySignature()

        if params['isValid']:
            mpinId = params["identity"]

            url = "{0}/user/{1}".format(options.RPSURL.rstrip("/"), mpinId)

            data = json.dumps({"activateKey": params["activateKey"]})
            client = tornado.httpclient.AsyncHTTPClient()
            response = yield tornado.gen.Task(client.fetch, url, method="POST", body=data)

            if (response.error):
                log.error("URL: {0}: Error: {1}".format(url, response.error))

                params["isValid"] = False
                params["errorMessage"] = "This verification link has already been used or has expired!"
            else:
                params["activated"] = True

        self.render("activate.html", **params)


class AuthenticateUserHandler(BaseHandler):

    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        self.content_type = 'application/json'

        try:
            data = json.loads(self.request.body)
            authOTT = data["mpinResponse"]["authOTT"]
        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return
        except KeyError:
            log.error("Invalid JSON structure.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return

        url = "{0}/authenticate".format(options.RPSURL.rstrip("/"))
        client = tornado.httpclient.AsyncHTTPClient()
        reqData = {
            "authOTT": authOTT,

            "logoutData": {"sessionToken": self.sessionId}
        }
        response = yield tornado.gen.Task(client.fetch, url, method="POST", body=json.dumps(reqData))

        try:
            data = json.loads(response.body)
            status = data["status"]
            userId = data["userId"]
            message = data["message"]
        except:
            log.error("Invalid data from RPS: {1}: {0}".format(url, response.body))
            message = "Server error"
            status = 500

        if (status == 200):
            # The Revocation check based on userId or mpinId can be performed here
            # The new status can be
            # 200 - Login successfull
            # 401 - Invalid PIN
            # 403 - User not authorized. Login denied without deleting the client's token.
            # 408 - The authentication has been expired.
            # 410 - Login denied permanently. Will delete the client's token.

            # If the RPS waitLoginResult option is set, /loginResult request must be made
            # It can contain logoutData and logoutURL for mobile Logout functionality

            url = "{0}/loginResult".format(options.RPSURL.rstrip("/"))
            client = tornado.httpclient.AsyncHTTPClient()
            reqData = {
                "authOTT": authOTT,
                "status": status,
                "message": message,
                "logoutData": {"sessionToken": self.sessionId, "userId": userId}
            }
            response = yield tornado.gen.Task(client.fetch, url, method="POST", body=json.dumps(reqData))

            if status == 200:
                # Login user. Update session information
                session = self.sessionId
                if session:
                    key = "s;{0}".format(session)
                    item = self.storage.find(key=key)
                    if item:
                        item.update(value=userId)
                    else:
                        self.storage.add(
                            key=key,
                            value=userId,
                            expire_time=datetime.datetime.now() + datetime.timedelta(seconds=3600)
                        )

        self.set_status(status, message)
        # Optional data can be send to the client's javascript handler.
        if options.requestOTP:
            ttlSeconds = 60
            nowtm = int(time.mktime(datetime.datetime.utcnow().timetuple()) * 1000)
            returnData = {
                "expireTime": nowtm + ttlSeconds * 1000,
                "ttlSeconds": ttlSeconds,
                "nowTime": nowtm
            }
        else:
            returnData = {"someUserData": "This will be handled by onSuccessLogin handler."}

        self.write(returnData)
        self.finish()


class AboutHandler(BaseHandler):
    def get(self):
        self.redirect("http://www.miracl.com/miracl-product-m-pin-core")


class ProtectedHandler(BaseHandler):
    def get(self, protected_page=None):
        if not self.loggedUser:
            self.set_flash("protected")
            self.redirect("/")
        else:
            template_name = "protected_{}.html".format(protected_page) if protected_page else "protected.html"
            self.render(template_name, welcome=(self.get_flash() == "login"), user=self.loggedUser, logoutWaitURL="/logoutWait")


class LogoutHandler(BaseHandler):
    def get(self):
        item = self.storage.find(key="s;{0}".format(self.sessionId))
        if item:
            item.delete()
        self.clear_cookie("mpindemo_session")
        self.redirect("/")

    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        sessionId = data.get("sessionToken")

        log.debug("Logout request. Session token: {0}".format(sessionId))

        item = self.storage.find(key="s;{0}".format(sessionId))
        loggedUser = item.value if item else None

        if (data.get("userId") != loggedUser):
            log.debug(" The logged user {0} does not match the requested user {1}".format(loggedUser, data.get("userId")))
            self.set_status(400, "Logout failed")
            return

        mobileLoginHandler.userLogged(sessionId, True)
        item = self.storage.find(key="s;{0}".format(sessionId))
        if item:
            item.delete()

    def options(self):
        self.set_status(200)
        self.finish()


class LogoutWaitHandler(BaseHandler):
    @tornado.web.asynchronous
    def get(self):
        '''Wait for user logout'''
        mobileLoginHandler.waitForLogin(self.onUserLoggedOut, self.sessionId, True)

    def onUserLoggedOut(self):
        if self.request.connection.stream.closed():
            return
        self.set_flash("forced_logout")
        self.write("OK")
        self.finish()

    def on_connection_close(self):
        mobileLoginHandler.cancelWait(self.sessionId, True)


class ServeMobileFileHandler(tornado.web.StaticFileHandler):
    def set_extra_headers(self, path):
        if path == "mpin.appcache":
            self.set_header("Content-Type", "text/cache-manifest")


class NotFoundHandler(BaseHandler):
    def get(self, *args):
        self.render("404.html")


# MAIN
class Application(tornado.web.Application):
    def __init__(self):
        staticPath = os.path.join(options.resourcesBasePath, "public")
        templatesPath = os.path.join(options.resourcesBasePath, "templates")
        mobilePath = options.mobileAppPath

        if mobilePath:
            handlers = [
                (r'/m', tornado.web.RedirectHandler, {"url": "/m/index.html"}),
                (r'/m/', tornado.web.RedirectHandler, {"url": "/m/index.html"}),
                (r'/m/(.*)', ServeMobileFileHandler, {'path': mobilePath}),
            ]
        else:
            handlers = []

        handlers.extend([
            (r"/", IndexHandler),
            (r"/login", IndexHandler),

            # M-PIN handlers
            (r"/{0}/(.*)".format(options.rpsPrefix), RPSRedirectHandler),
            (r"/mpinVerify", VerifyUserHandler),
            (r"/mpinAuthenticate", AuthenticateUserHandler),
            (r"/mpinActivate", mpinActivateHandler),
            (r"/mpinPermitUser", mpinPermitUserHandler),

            # Application handlers
            (r"/protected/(.*)", ProtectedHandler),
            (r"/protected", ProtectedHandler),
            (r"/about", AboutHandler),
            (r"/logout", LogoutHandler),
            (r"/logoutWait", LogoutWaitHandler),

        ])

        if os.path.exists(os.path.join(templatesPath, "404.html")):
            handlers.extend([(r"/(.*)", NotFoundHandler)])

        settings = {
            "template_path": templatesPath,
            "static_path": staticPath,
            "static_url_prefix": "/public/",
            "cookie_secret": options.cookieSecret,
            "xsrf_cookies": False
        }

        super(Application, self).__init__(handlers, **settings)

        storage_cls = get_storage_cls()
        self.storage = storage_cls(tornado.ioloop.IOLoop.instance(), 'key')


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

    if not options.cookieSecret:
        log.error("cookieSecret option required")
        sys.exit(1)

    detectProxy()
    mailer.setup(options.smtpServer, options.smtpPort, options.emailSender, options.smtpUseTLS)

    log.info("Server starting on {0}:{1}...".format(options.address, options.port))

    http_server = Application()
    http_server.listen(options.port, options.address, xheaders=True)
    io_loop = tornado.ioloop.IOLoop.instance()

    if options.autoReload:
        log.debug("Starting autoreloader")

        tornado.autoreload.watch(CONFIG_FILE)
        for f in os.listdir(http_server.settings["template_path"]):
            fn = os.path.join(http_server.settings["template_path"], f)
            if os.path.isfile(fn):
                tornado.autoreload.watch(fn)
        tornado.autoreload.start(io_loop)

    log.info("Server started. Listening on {0}:{1}".format(options.address, options.port))
    io_loop.start()


class ServiceDaemon(Daemon):
    def run(self):
        main()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("start", "stop"):
        action = sys.argv.pop(1)
        logFile = os.path.join(BASE_DIR, "mpinDemo.log")
        pidFile = os.path.join(BASE_DIR, "mpinDemo.pid")

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
