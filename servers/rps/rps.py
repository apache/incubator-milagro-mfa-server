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
import hashlib
import json
import os
import random
import sys
import time
import urllib
from urlparse import urlparse

import tornado.autoreload
import tornado.gen
import tornado.httpclient
import tornado.httpserver
import tornado.web
import tornado.websocket
from tornado.httputil import url_concat
from tornado.log import app_log as log
from tornado.options import define, options
from tornado.web import HTTPError

from mpin_utils.common import (
    detectProxy,
    getLogLevel,
    Keys,
    Seed,
    SIGNATURE_EXPIRES_OFFSET_SECONDS,
    signMessage,
    Time,
)
from mpin_utils import secrets
from storage import get_storage_cls
from dynamic_options import (
    generate_dynamic_options,
    process_dynamic_options,
)

from mobile_flow import MobileFlow

if os.name == "posix":
    from mpDaemon import Daemon
elif os.name == "nt":
    from mpWinService import Service as Daemon
else:
    raise Exception("Unsupported platform: {0}".format(os.name))


VERSION = '0.3'
BASE_DIR = os.path.dirname(__file__)
CONFIG_FILE = os.path.join(BASE_DIR, "config.py")
MOBILE_LOGIN_AUTHENTICATION_TIMEOUT_SECONDS = 10

PASS1_EXPIRES_TIME = 15
PERMITS_MIN, PERMITS_MAX = 7, 13


# OPTIONS

# general options
define("configFile", default=os.path.join(BASE_DIR, "config.py"), type=unicode)
define("address", default="127.0.0.1", type=unicode)
define("port", default=8011, type=int)
define("allowOrigin", default="*")
define("dynamicOptionsURL", default=None, type=unicode)

# debugging options
define("autoReload", default=False, type=bool)
define("logLevel", default="ERROR", type=unicode)

# time synchronization options
define("timePeriod", default=86400000, type=int)
define("syncTime", default=True, type=bool)

# security options
define("credentialsFile", default=os.path.join(BASE_DIR, "credentials.json"), type=unicode)
define("EntropySources", default="certivox:100", type=unicode)
define("seedValueLength", default=100, type=int)

# customer DTA service discovery options
define("DTALocalURL", default="", type=unicode)

# access number options
define("accessNumberExpireSeconds", default=300, type=int)
define("accessNumberExtendValiditySeconds", default=5, type=int)
define("accessNumberUseCheckSum", default=True, type=bool)

# authentication options
define("waitForLoginResult", default=False, type=bool)
define("VerifyUserExpireSeconds", default=3600, type=int)
define("maxInvalidLoginAttempts", default=3, type=int)
define("cacheTimePermits", default=True, type=bool)

# OTP options
define("requestOTP", default=False, type=bool)
define("OTTLength", default=16, type=int)

# RPA options
define("RPAVerifyUserURL", default="", type=unicode)
define("RPAPermitUserURL", default="", type=unicode)
define("RPAAuthenticateUserURL", default="", type=unicode)
define("RegisterForwardUserHeaders", default="", type=unicode)
define("LogoutURL", default="", type=unicode)

# PIN pad client options
define("rpsBaseURL", default="")
define("rpsPrefix", default="rps")
define("setDeviceName", default=False, type=bool)

# mobile client config
define("mobileUseNative", default=False, type=bool)
define("mobileConfig", default=None, type=list)
define("mobileService", default=None, type=dict)
define("useNFC", default=False, type=bool)
define("serviceName", default="", type=unicode)
define("serviceType", default="online", type=unicode)
define("serviceIconUrl", default="", type=unicode)


# Mapping between local names of dynamic options and names from json
# in the form `remote_name`: `local_name`
# Only options that have mapping are processed
DYNAMIC_OPTION_MAPPING = {
    'time_synchronization': 'syncTime',
    'time_synchronization_period': 'timePeriod',
    'mobile_use_native': 'mobileUseNative',
    'mobile_client_config': 'mobileConfig',
    'mobile_service': 'mobileService',
}


# Dynamic options handlers
def handle_time_synchronization_update(updated, application, initial):

    log.debug("Handling time synchronization")
    if not any(x in updated for x in ('syncTime', 'timePeriod')) and not initial:
        log.debug("Nothing to do on time synchronization")
        return

    def _stop_scheduler():
            try:
                application.time_sync_scheduler.stop()
                log.debug("Stopped time sync schduler")
            except:
                pass
    if options.syncTime and (options.timePeriod > 0):
        _stop_scheduler()
        application.time_sync_scheduler \
            = tornado.ioloop.PeriodicCallback(
                Time.getTime,
                options.timePeriod,
                io_loop=application.io_loop)
        application.time_sync_scheduler.start()
        log.debug(
            "Started time sync schduler with period {0}"
            .format(options.timePeriod))
    else:
        _stop_scheduler()


# Convenience variable - list of dynamic options update handlers
DYNAMIC_OPTION_HANDLERS = [
    handle_time_synchronization_update,
]


# UTILITIES
def makeMPinID(userId, isMobile):
    endUserData = {
        "issued": str(Time.syncedNow()),
        "userID": userId,
        "mobile": int(isMobile or 0),
        "salt": os.urandom(16).encode("hex")
    }

    mpin_id = json.dumps(endUserData)

    return mpin_id.encode("hex")


def verifyToken(token):
    """A method for verifying the authentication token.

       n.b. The message variable should not be returned in a deployed application
    """
    successCode = int(token["successCode"])
    pinError = int(token["pinError"])

    # Get current time and token expired time
    expiresStr = token["expires"].replace(" ", "T").replace("Z", "")
    expiresTime = datetime.datetime.strptime(expiresStr, '%Y-%m-%dT%H:%M:%S')
    syncedTime = Time.syncedNow()

    # Check if token has expired.
    if syncedTime > expiresTime:
        fail = 1
        status = 401
        reason = "Authentication Failed. Token Expired."

    elif successCode != 0:
        if pinError == 0:  # No token.
            fail = 1
            status = 401
            reason = "Authentication Failed. Invalid Token."
        else:
            # Entering wrong PIN.
            fail = 1
            status = 401
            reason = "Authentication Failed. Invalid PIN."
    else:
        # Successful authentication
        fail = 0
        status = 200
        reason = "OK"

    return (fail, status, reason)


# BASE HANDLERS
class BaseHandler(tornado.web.RequestHandler):

    def set_default_headers(self):
        try:
            log.debug("Origin Header %s" % self.request.headers['Origin'])
            if self.request.headers['Origin'] in options.allowOrigin:
                self.set_header("Access-Control-Allow-Origin", self.request.headers['Origin'])
            elif "*" in options.allowOrigin:
                self.set_header("Access-Control-Allow-Origin", "*")
        except:
            log.debug("Origin header not defined")
        self.set_header("Access-Control-Allow-Credentials", "true")
        self.set_header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
        self.set_header("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate")

    def write_error(self, status_code, **kwargs):
        self.set_status(status_code, reason=self._reason)
        self.content_type = 'application/json'
        self.write({'version': VERSION, 'message': self._reason})

    def options(self, *args, **kwargs):
        self.set_status(200, reason="OK")
        self.content_type = 'application/json'
        self.write({'version': VERSION, 'message': "options request"})
        self.finish()
        return

    def finish(self, *args, **kwargs):
        if self._status_code == 401:
            self.set_header("WWW-Authenticate", "Authenticate")
        super(BaseHandler, self).finish(*args, **kwargs)

    @property
    def storage(self):
        return self.application.storage


class PrivateBaseHandler(BaseHandler):

    def prepare(self):
        # TODO: Check the remoteIP option
        # allow connections from whitelisted IP's
        # print self.request.remote_ip
        # self.set_status(404)
        # self.finish()
        pass


# PUBLIC HANDLERS
class ClientSettingsHandler(BaseHandler):
    def get(self):
        self.set_header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
        self.set_header("Pragma", "no-cache")
        self.set_header("Expires", "Sat, 26 Jul 1997 05:00:00 GMT")

        baseURL = "{0}/{1}".format(options.rpsBaseURL, options.rpsPrefix.strip("/"))
        params = {
            "certivoxURL": Keys.certivoxServer(),
            "signatureURL": "{0}/signature".format(baseURL),
            "registerURL": "{0}/user".format(baseURL),
            "timePermitsURL": "{0}/timePermit".format(baseURL),
            "timePermitsStorageURL": "{0}".format(Keys.timePermitsStorageURL),
            "setupDoneURL": "{0}/setupDone".format(baseURL),
            "mpinAuthServerURL": baseURL,
            "authenticateURL": options.RPAAuthenticateUserURL,
            "mobileAuthenticateURL": "{0}/authenticate".format(baseURL),
            "setDeviceName": options.setDeviceName,
            "accessNumberUseCheckSum": options.accessNumberUseCheckSum,

            "appID": Keys.app_id,
            "requestOTP": options.requestOTP,
            "seedValue": secrets.generate_random_number(
                self.application.server_secret.rng, options.seedValueLength),

            "useWebSocket": False,

            "accessNumberDigits": 7 if options.accessNumberUseCheckSum else 6,
            "cSum": 1,
            "useNFC": options.useNFC,
        }

        if not options.requestOTP:
            params["accessNumberURL"] = "{0}/access".format(baseURL)
            params["getAccessNumberURL"] = "{0}/getAccessNumber".format(baseURL)

        if options.mobileUseNative:
            params["getQrUrl"] = "{0}/getQrUrl".format(baseURL)
            params["codeStatusURL"] = "{0}/codeStatus".format(baseURL)

        self.write(params)
        self.finish()


class RPSUserHandler(BaseHandler):

    @tornado.web.asynchronous
    @tornado.gen.engine
    def put(self, mpinId):

        try:
            data = json.loads(self.request.body)
            mobile = int(data.get("mobile", "0"))
            userId = data.get("userId")
            deviceName = data.get("deviceName", "")
            oldRegOTT = data.get("regOTT")

            if not userId:
                log.error("Missing userId")
                log.debug(self.request.body)
                self.set_status(400, reason="BAD REQUEST. INVALID USERID")
                self.finish()
                return

        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return

        if mpinId.strip("/"):
            mpinId = mpinId.strip("/")
            log.debug("Reactivation request for mpinId: {0}".format(mpinId))

            updateItem = self.storage.find(stage="register", mpinId=mpinId)
            if not updateItem:
                mpinId = None
                oldRegOTT = None
                log.error("Missing or invalid mpinID. Will generate a new mpinID")

            elif updateItem.regOTT != oldRegOTT:
                log.error("Missing or invalid regOTT")
                log.debug(self.request.body)
                self.set_status(400, reason="BAD REQUEST. INVALID REGOTT")
                self.finish()
                return

        if not mpinId:
            # Generate new mpinID
            updateItem = None
            mpinId = makeMPinID(userId, mobile)
            log.debug("New mpinID generated for user {0}: {1}".format(userId, mpinId))

        userData = data.get("userData")

        # Verify user >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        # Generate activateKey
        regOTT = oldRegOTT or secrets.generate_ott(options.OTTLength, self.application.server_secret.rng, "hex")
        activateKey = signMessage("{0}{1}".format(mpinId, regOTT), Keys.app_key)
        nowTime = Time.syncedNow()
        expireTime = nowTime + datetime.timedelta(seconds=options.VerifyUserExpireSeconds)

        requestBody = json.dumps({
            "userId": userId,
            "mpinId": mpinId,
            "mobile": mobile,
            "activateKey": activateKey,
            "expireTime": Time.DateTimeToISO(expireTime),
            "resend": bool(updateItem),
            "deviceName": deviceName,
            "userData": userData or ""
        })

        if updateItem:
            updateItem.delete()

        client = tornado.httpclient.AsyncHTTPClient()

        pr = urlparse(self.request.full_url())
        base_url = "{0}://{1}".format(pr.scheme, pr.netloc)

        headers = {
            "RPS-BASE-URL": base_url
        }

        # Forward headers to the RPA
        if options.RegisterForwardUserHeaders:
            allHeaders = options.RegisterForwardUserHeaders == "*"
            rHeaders = map(lambda x: x.strip().lower(), options.RegisterForwardUserHeaders.split(","))
            for h in self.request.headers:
                if allHeaders or (h.lower() in rHeaders):
                    headers[h] = self.request.headers[h]

        RPAVerifyUserURL = options.RPAVerifyUserURL

        if not RPAVerifyUserURL:
            log.error("RPAVerifyUserURL option not set! Unable to make Verify request")
            self.set_status(400, "RPAVerifyUserURL option not set.")
            self.finish()
            return

        # Make the verify request to the RPA
        response = yield tornado.gen.Task(client.fetch, RPAVerifyUserURL, method="POST", headers=headers, body=requestBody)

        if response.error:
            log.error("RPA verify request error: {0}. Code: {1}, Reason: {2}".format(response.error, response.code, response.reason))
            error = response.code
            if error >= 500:
                error = 500

            self.set_status(error)
            self.finish()
            return

        forceActivate = False
        if response.body:
            try:
                responseData = json.loads(response.body)
                forceActivate = responseData.get("forceActivate", forceActivate)
            except:
                log.error("RPA verify request: Invalid JSON response: {0}".format(response.body))
                self.set_status(500)
                self.finish()
                return

        if forceActivate:
            log.debug("RPA response: force_activate. Activating UserID: {0}".format(userId))

        if forceActivate:
            active = activateKey
        else:
            active = 0

        log.debug("New regOTT generated: {0}. ForceActivate: {1}".format(regOTT, forceActivate))

        self.storage.add(
            expire_time=expireTime,
            stage="register",
            mpinId=mpinId,
            regOTT=regOTT,
            active=active
        )

        # Response to the client
        responseData = {
            "mpinId": mpinId,
            "regOTT": regOTT,
            "expireTime": expireTime.isoformat(),
            "nowTime": nowTime.isoformat(),
            "active": forceActivate
        }

        self.write(responseData)
        self.finish()


class RPSSignatureHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, mpinId):

        regOTT = self.get_argument("regOTT")

        log.debug("ClientSecret request for mpinID: {0}".format(mpinId))

        mpinData = json.loads(mpinId.decode("hex"))
        mobile = mpinData.get("mobile", 0)

        I = self.storage.find(stage="register", mpinId=mpinId)
        if not I:
            log.debug("MpinID {0} not found.".format(mpinId))
            self.set_status(400, "M-Pin ID not found.")
            self.finish()
            return

        # Verify regOTT
        if I.regOTT != regOTT:
            log.error("MpinID {0} regOTT does not match!".format(mpinId))
            I.delete()
            self.set_status(400, "M-Pin ID not found.")
            self.finish()
            return

        # Verify Activated
        if I.active != signMessage("{0}{1}".format(mpinId, regOTT), Keys.app_key):
            log.debug("MpinID {0} is not activated!".format(mpinId))
            self.set_status(401, "M-PinID not active.")
            self.finish()
            return

        # Get hash of M-PIN ID
        hash_mpin_id_hex = hashlib.sha256(mpinId.decode("hex")).hexdigest()

        # Get hash of UserID ID
        hash_user_id = hashlib.sha256('{user_id}{salt}'.format(
            user_id=mpinData['userID'],
            salt=hashlib.sha256(self.application.server_secret.server_secret).hexdigest(),
        )).hexdigest()

        # Generate signed params
        path = "clientSecret"
        expires = Time.syncedISO(seconds=SIGNATURE_EXPIRES_OFFSET_SECONDS)
        hash_user_id = ""
        M = str("%s%s%s%s%s" % (path, Keys.app_id, hash_mpin_id_hex, hash_user_id, expires))
        signature_hex = signMessage(M, Keys.app_key)

        param_values = {
            'app_id': Keys.app_id,
            'expires': expires,
            'hash_mpin_id': hash_mpin_id_hex,
            'hash_user_id': hash_user_id,
            'mobile': mobile,
            'signature': signature_hex,
        }

        url = "{0}/{1}".format(options.DTALocalURL.rstrip("/"), path)
        urlParams = url_concat(url, param_values)

        client = tornado.httpclient.AsyncHTTPClient()
        response = yield tornado.gen.Task(client.fetch, urlParams, method="GET")

        if response.error:
            log.error("DTA clientSecret failed, URL: {0}. Code: {1}, Reason: {2}".format(urlParams, response.code, response.reason))
            self.set_status(500)
            self.finish()
            return

        if response.body:
            try:
                responseData = json.loads(response.body)
                clientSecretShare = responseData["clientSecret"]
            except:
                log.error("DTA /clientSecret Failed. Invalid JSON response".format(response.body))
                self.set_status(500)
                self.finish()
                return

        I.delete()

        params = urllib.urlencode(param_values)
        data = {
            "params": params,
            "clientSecretShare": clientSecretShare
        }

        self.write(data)
        self.finish()


class RPSTimePermitHandler(BaseHandler):

    def __init__(self, *args, **kwargs):
        super(RPSTimePermitHandler, self).__init__(*args, **kwargs)
        self.http_client = tornado.httpclient.AsyncHTTPClient()

    @tornado.gen.coroutine
    def get_time_permits(self, hash_mpin_id_hex, signature):
        # Get time permit from the local D-TA
        url = url_concat(
            "{0}/{1}".format(options.DTALocalURL.rstrip("/"), "timePermits"), {
                'hash_mpin_id': hash_mpin_id_hex,
                'signature': signature,
                'count': random.randint(PERMITS_MIN, PERMITS_MAX) if options.cacheTimePermits else 1})
        response = yield self.http_client.fetch(url)

        if response.error:
            log.error("DTA timePermit failed, URL: {0}. Code: {1}, Reason: {2}".format(url, response.code, response.reason))
            raise HTTPError(500)

        if response.body:
            try:
                response_data = json.loads(response.body)
                raise tornado.gen.Return(response_data["timePermits"])
            except (ValueError, KeyError):
                log.error("DTA /timePermit Failed. Invalid JSON response".format(
                    response.body))
                raise HTTPError(500)

    def cache_time_permits(self, time_permits, hash_mpin_id_hex):
        # Cache them in storage
        for date_epoch, time_permit in time_permits.iteritems():
            try:
                date_epoch = int(date_epoch)
            except ValueError:
                log.error("DTA /timePermit Failed. Date invalid integer")
                raise HTTPError(500)

            self.storage.add(
                expire_time=datetime.datetime.fromtimestamp(date_epoch * 60 * 1440) + datetime.timedelta(days=1),
                time_permit_id=hash_mpin_id_hex,
                time_permit_date=date_epoch,
                time_permit=time_permit)

    @tornado.gen.coroutine
    def get_time_permit(self, hash_mpin_id_hex, date_epoch, signature):
        """Get time permit from cache or request new."""
        if options.cacheTimePermits:
            time_permit_item = self.storage.find(time_permit_id=hash_mpin_id_hex, time_permit_date=date_epoch)
            if time_permit_item:
                # Get time permit from cache
                raise tornado.gen.Return(time_permit_item.time_permit)

        # No cached time permits for this mpin id, request new from D-TA
        time_permits = yield self.get_time_permits(hash_mpin_id_hex, signature)
        if options.cacheTimePermits:
            self.cache_time_permits(time_permits, hash_mpin_id_hex)

        # Return the one for today
        if str(date_epoch) not in time_permits:
            log.error("DTA /timePermit Failed. No time permit for today")
            raise HTTPError(500)
        raise tornado.gen.Return(time_permits[str(date_epoch)])

    @tornado.gen.coroutine
    def get(self, mpin_id):
        # Check revocation status of mpin id.
        if options.RPAPermitUserURL:
            response = yield self.http_client.fetch(
                url_concat(options.RPAPermitUserURL, {"mpin_id": mpin_id}),
                raise_error=False)

            if response.code != 200:
                # RPA rejects this mpin id
                raise HTTPError(response.code)

        hash_mpin_id_hex = hashlib.sha256(mpin_id.decode("hex")).hexdigest()
        today_epoch = secrets.today()
        signature = signMessage(hash_mpin_id_hex, Keys.app_key)
        time_permit = yield self.get_time_permit(hash_mpin_id_hex, today_epoch, signature)

        self.set_header("Cache-Control", "no-cache")
        self.finish({
            "date": today_epoch,
            "signature": signature,
            "storageId": hash_mpin_id_hex,
            'message': "M-Pin Time Permit Generated",
            'timePermit': time_permit,
            'version': VERSION,
        })


class RPSSetupDoneHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self, mpinId):
        log.debug("Setup done for mpinId: {0}".format(mpinId))
        self.set_status(200)
        self.finish()


class RPSGetAccessNumberHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        # Generate request for MPinWIDServer for WID
        wId = secrets.generate_random_webid(self.application.server_secret.rng, options.accessNumberUseCheckSum)

        while wId is None or (self.storage.find(stage="auth", wid=wId)):
            if wId is None:
                log.debug("WebId is None".format(wId))
            else:
                log.debug("WebId {0} already exists. Generating a new one".format(wId))
            wId = secrets.generate_random_webid(self.application.server_secret.rng, options.accessNumberUseCheckSum)

        log.debug("New webId generated: {0}." .format(wId))

        webOTT = secrets.generate_ott(options.OTTLength, self.application.server_secret.rng, "hex")

        nowTime = Time.syncedNow()
        expirePinPadTime = nowTime + datetime.timedelta(seconds=options.accessNumberExpireSeconds)
        expireTime = expirePinPadTime + datetime.timedelta(seconds=options.accessNumberExtendValiditySeconds)

        self.storage.add(stage="auth", expire_time=expireTime, webOTT=webOTT, wid=wId)

        params = {
            "ttlSeconds": options.accessNumberExpireSeconds,
            "accessNumber": wId,
            "webOTT": webOTT,
            "localTimeStart": Time.DateTimetoEpoch(nowTime),
            "localTimeEnd": Time.DateTimetoEpoch(expirePinPadTime)
        }

        self.write(params)
        self.finish()


class RPSGetQrUrlHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        mobileFlow = MobileFlow(self.application, self.storage)
        params = mobileFlow.generate_qr(mobileFlow.generate_wid())

        self.write(params)
        self.finish()


class RPSAccessHanler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        try:
            data = json.loads(self.request.body)
            webOTT = data["webOTT"]
        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return

        params = MobileFlow(self.application, self.storage).get_app_status(webOTT)

        self.write(params)
        self.finish()


class RPSAuthenticateHandler(BaseHandler):

    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        try:
            data = json.loads(self.request.body)
            data = data["mpinResponse"]
            authOTT = data["authOTT"]
        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return
        except KeyError:
            log.error("Invalid JSON data structure")
            log.debug(data)
            self.set_status(400, reason="BAD REQUEST. INVALID DATA")
            self.finish()
            return

        I = self.storage.find(stage="auth", authOTT=authOTT)

        if not I:
            log.error("Invalid or expired authOTT")
            status = 412
            message = "Invalid or expired access number"
            userId = ""
            mpinId = ""
            response = {"message": message}

        else:
            authToken = I.authToken
            mpinId = authToken["mpin_id"].encode("hex")
            identity = json.loads(authToken["mpin_id"])
            userId = identity["userID"]

            (fail, status, reason) = verifyToken(authToken)

            aI = self.storage.find(stage="attempts", mpinId=mpinId)
            attemptsCount = aI and aI.attemptsCount or 0
            if attemptsCount >= options.maxInvalidLoginAttempts:
                fail = 1

            if fail == 0:
                # Delete invalid login attempts if any
                if aI:
                    aI.delete()

                # Authentication successful
                message = "Authentication successful"

                # Wait for browser authentication and get Logout information
                I.update(status=status, message=message)

                main_loop = tornado.ioloop.IOLoop.instance()

                # Wait until the browser is ready or timeout occurs
                timeOut = Time.syncedNow(seconds=MOBILE_LOGIN_AUTHENTICATION_TIMEOUT_SECONDS)
                while (not I.browserReady) and (Time.syncedNow() < timeOut):
                    yield tornado.gen.Task(main_loop.add_timeout, time.time() + 1)

                # Get the new status. Status can be changed with the /loginResult request
                if status != I.status:
                    status = I.status
                    message = I.message
                    response = {"message": message}

                elif I.browserReady:
                    logoutURL = I.logoutURL or ""
                    logoutData = I.logoutData or ""
                    response = {"logoutURL": logoutURL, "logoutData": logoutData}
                else:
                    # Timeout occured
                    status = 408
                    message = "Authentication timed out"
                    response = {"message": message}

            else:
                attemptsCount += 1
                if aI:
                    aI.update(attemptsCount=attemptsCount)
                else:
                    self.storage.add(stage="attempts", mpinId=mpinId, attemptsCount=attemptsCount)

                if attemptsCount >= options.maxInvalidLoginAttempts:
                    status = 410

                log.debug("Wrong PIN for user {0}.".format(userId))
                message = "Wrong PIN."
                response = {"message": message}
                I.update(status=status, message=message)

        self.set_status(status, message)
        self.write(response)
        self.finish()


class StatusHandler(BaseHandler):

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self):
        reason = "active"
        self.set_status(200, reason=reason)
        self.write({'version': VERSION, 'message': reason})

        self.finish()


class ServiceHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self):
        if options.mobileService:
            params = json.dumps(options.mobileService)
            self.write(params)
        else:
            self.set_status(403)
        self.finish()


class DefaultHandler(BaseHandler):
    def get(self, input):
        reason = "URI NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'version': VERSION, 'service_name': 'M-Pin authentication server', 'message': reason})
        return

    def post(self, input):
        reason = "URI NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'version': VERSION, 'service_name': 'M-Pin authentication server', 'message': reason})
        return

    def put(self, input):
        reason = "URI NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'version': VERSION, 'service_name': 'M-Pin authentication server', 'message': reason})
        return

    def delete(self, input):
        reason = "URI NOT FOUND"
        self.set_status(404, reason=reason)
        self.write({'version': VERSION, 'service_name': 'M-Pin authentication server', 'message': reason})
        return


# AUTHENTICATION HANDLER
class Pass1Handler(BaseHandler):
    """
    ..  apiTextStart

    *Description*

      Implements the first pass of the M-Pin Protocol

    *URL structure*

      ``/pass1``

    *Version*

      0.3

    *HTTP Request Method*

      POST

    *Request Data*

      JSON request::

        {
          "mpin_id":  "7b22...227d",
          "U":    "0409...3d9c",
          "UT":   "0402...d1d1",
          "pass" : 1
        }

      mpin_id is the hex encoded M-Pin ID, U is x.hash(mpin_id) and UT is
      x.(hash(mpin_id) + hash(data||hash(mpin_id)))

    *Returns*

      JSON response::

        {
          "y" : "212a...8d08",
          "version" : "0.3",
          "message" : "OK",
          "pass" : 1
        }

      y  is a 256 bit random value.

    *Status-Codes and Response-Phrases*

      ::

        Status-Code          Response-Phrase

        200                  OK
        403                  Invalid data received. <argument> argument missing
        403                  Invalid data received. No JSON object could be decoded
        403                  Invalid data received. Non-hexadecimal digit found
        500                  Failed to generate y
        500                  Failed to add pass one to memory

    ..  apiTextEnd

    """
    def post(self):
        # Remote request information
        if 'User-Agent' in self.request.headers.keys():
            UA = self.request.headers['User-Agent']
        else:
            UA = 'unknown'
        request_info = '%s %s %s %s ' % (self.request.path, self.request.remote_ip, UA, Time.syncedISO())

        try:
            receive_data = tornado.escape.json_decode(self.request.body)
            mpin_id = receive_data['mpin_id'].decode("hex")
            ut_hex = receive_data['UT']
            u_hex = receive_data['U']
        except KeyError as ex:
            reason = "Invalid data received. %s argument missing" % ex.message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        except (ValueError, TypeError) as ex:
            reason = "Invalid data received. %s" % ex.message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        log.debug("%s %s" % (request_info, receive_data))

        # Server generates Random number Y and sends it to Client
        try:
            y_hex = self.application.server_secret.get_pass1_value()
        except secrets.SecretsError as e:
            log.error(e.message)
            self.set_status(500, reason=e.message)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': e.message})
            self.finish()
            return

        # Store Pass1 values
        self.storage.add(
            expire_time=Time.syncedISO(seconds=PASS1_EXPIRES_TIME),
            stage="pass1",
            mpinId=mpin_id.encode('hex'),
            ut=ut_hex,
            u=u_hex,
            y=y_hex,
        )

        log.info("%s Stored Pass1 values" % request_info)

        reason = "OK"
        self.set_status(200, reason=reason)
        self.content_type = 'application/json'
        return_data = {
            'version': VERSION,
            'y': y_hex,
            'pass': 1,
            'message': reason
        }
        log.debug("%s %s" % (request_info, return_data))
        self.write(return_data)
        self.finish()
        return


class Pass2Handler(BaseHandler):
    """
    ..  apiTextStart

    *Description*

      Implements the second pass of the M-Pin Protocol. The result will be the authOTP.
      At this point the authentication token has also been written to the RPS.
      An authOTT will always be returned even if authentication fails.

    *URL structure*

      ``/pass2``

    *Version*

      0.3

    *HTTP Request Method*

      POST

    *Request Data*

      JSON request::

        {
          "WID" : "123456"
          "V" : "0411...05f6a",
          "pass" : 2,
          "OTP" : <1||0>
        }

      WID is web identifier used for mobile authentication
      When OTP is set to one this indicates that the radius OTP should be
      generated.  V is a parameter used to perform the final step of the M-Pin
      algorithm.

    *Returns*

      JSON response::

        {
          "OTP": "155317",
          "authOTT": "31ba0ed5efb75d91ef69a2b7eb1d3a26",
          "pass": 2,
          "version": "0.3"
        }

      OTP is the radius one time password. authOTT is the password used to log into the
      Customer's website.

    *Status-Codes and Response-Phrases*

      ::

        Status-Code          Response-Phrase

        200                  OK
        403                  Invalid data received. <argument> argument missing
        403                  Invalid data received. No JSON object could be decoded
        403                  Invalid data received. Non-hexadecimal digit found
        500                  Pass one data is not in memory

    ..  apiTextEnd

    """
    @tornado.gen.coroutine
    def post(self):
        # Remote request information
        if 'User-Agent' in self.request.headers.keys():
            UA = self.request.headers['User-Agent']
        else:
            UA = 'unknown'
        request_info = '%s %s %s %s ' % (self.request.path, self.request.remote_ip, UA, Time.syncedISO())

        try:
            receive_data = tornado.escape.json_decode(self.request.body)
            mpin_id_hex = receive_data['mpin_id']
            mpin_id = mpin_id_hex.decode('hex')
            WID = receive_data['WID']
            OTPEn = receive_data['OTP']
            v_data = receive_data['V'].decode("hex")
        except KeyError as ex:
            reason = "Invalid data received. %s argument missing" % ex.message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        except (ValueError, TypeError) as ex:
            reason = "Invalid data received. %s" % ex.message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        log.debug("%s %s" % (request_info, receive_data))

        # Get pass one values
        pass1Value = self.storage.find(stage="pass1", mpinId=mpin_id_hex)

        if pass1Value:
            u = pass1Value.u.decode("hex")
            ut = pass1Value.ut.decode("hex")
            y = pass1Value.y.decode("hex")
        else:
            reason = "Invalid pass one data"
            log.error("%s %s" % (request_info, reason))
            self.set_status(500, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        log.info("%s loaded Pass1 values" % request_info)

        # Generate OTP value
        if int(OTPEn) == 1:
            OTP = "{0:06d}".format(
                secrets.generate_otp(self.application.server_secret.rng))
        else:
            OTP = '0'

        log.info("%s generate OTP" % request_info)

        successCode = self.application.server_secret.validate_pass2_value(
            mpin_id, u, ut, y, v_data)

        pinError = 0
        pinErrorCost = 0

        # Authentication Token expiry
        expires = Time.syncedISO(seconds=SIGNATURE_EXPIRES_OFFSET_SECONDS)

        # Form Authentication token
        token = {
            "mpin_id": mpin_id,
            "mpin_id_hex": mpin_id_hex,
            "successCode": successCode,
            "pinError": pinError,
            "pinErrorCost": pinErrorCost,
            "expires": expires,
            "WID": WID,
            "OTP": OTP
        }
        log.debug("%s M-Pin Auth token: %s" % (request_info, token))

        # Form authentication 128 hex encoded One Time Password
        authOTT = secrets.generate_auth_ott(self.application.server_secret.rng)

        # Form message to return to client #
        return_data = {
            'version': VERSION,
            'pass': 2,
            'authOTT': authOTT
        }

        if int(OTPEn) == 1:
            return_data['OTP'] = OTP

        if WID != "0":
            # Login with mobile
            I = self.storage.find(stage="auth", wid=WID)

            wid_flow = "wid"
            flow = "mobile"

            # if not I:
            #     log.error("Invalid or expired access number: {0} for mpinid: {1}".format(WID, mpinId))
            #     self.set_status(412, reason="INVALID OR EXPIRED ACCESS NUMBER")
            #     self.finish()
            #     return

            if I:
                I.update(authOTT=authOTT, mpinid=mpin_id, authToken=token)

        else:
            wid_flow = "browser"

            if int(token.get("OTP", "0")) != 0:
                flow = "OTP"
            else:
                flow = "Browser"

            self.storage.add(
                expire_time=Time.ISOtoDateTime(expires),
                stage="auth",
                authOTT=authOTT,
                mpinId=mpin_id,
                wid="",
                webOTT=0,
                authToken=token
            )

        log.debug("New M-Pin Authentication token / {0}. Flow: {1}".format(wid_flow, flow))

        # Always send 200 to PIN Pad even if the user is not authenticated
        reason = "OK"
        log.debug("%s %s" % (request_info, return_data))
        self.set_status(200, reason=reason)
        self.content_type = 'application/json'
        self.write(return_data)
        self.finish()
        return


# PRIVATE HANDLERS
class ManageGetStackInfoHandler(PrivateBaseHandler):

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self):
        # Get signed API settings

        path = "apiSettings"
        expires = Time.syncedISO(seconds=SIGNATURE_EXPIRES_OFFSET_SECONDS)
        M = "{0}{1}{2}" .format(path, Keys.app_id, expires)
        signature_hex = signMessage(M, Keys.app_key)

        param_values = {
            'app_id': Keys.app_id,
            'expires': expires,
            'signature': signature_hex,
        }

        url = "{0}/{1}".format(Keys.api_url.rstrip("/"), path)
        urlParams = url_concat(url, param_values)

        client = tornado.httpclient.AsyncHTTPClient()
        response = yield tornado.gen.Task(client.fetch, urlParams, method="GET")

        status = 200

        if (response.error):
            log.error("API Request Error URL: {0}: {1}: {2}".format(url, response.error, response.body))
            status = 500
            self.set_status(status)
            self.finish()
            return

        resp_data = None
        try:
            resp_data = json.loads(response.body)
        except ValueError:
            log.error("Cannot decode JSON response from API {0}: {1}".format(url, response.body))
            status = 500
            self.set_status(status)
            self.finish()
            return

        expires = Time.syncedISO(hours=1)
        M = "{0}{1}" .format(Keys.app_id, expires)
        signature = signMessage(M, Keys.app_key)

        manage_auth_params = {
            "signature": signature,
            "expires": expires,
            "app_id": Keys.app_id
        }

        result = {
            "managementConsoleURL": resp_data.get("managementConsoleURL", ""),
            "license_info": resp_data.get("license_info", {}),
            "manage_auth": manage_auth_params
        }

        self.write(result)
        self.finish()


class UserHandler(PrivateBaseHandler):
    def post(self, mpinId):
        log.debug("Request for activationg mpinid: {0}".format(mpinId))

        try:
            data = json.loads(self.request.body)
            activateKey = data["activateKey"]
        except:
            log.error("Invalid JSON request: {0}".format(self.request.body))
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return

        I = self.storage.find(stage="register", mpinId=mpinId)
        if not I:
            log.debug("MpinID {0} not found.".format(mpinId))
            self.set_status(401, "M-Pin ID not found.")
            self.finish()
            return

        I.update(active=activateKey)
        self.set_status(200)
        self.finish()


class AuthenticateHandler(PrivateBaseHandler):

    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        OTP = ""

        try:
            data = json.loads(self.request.body)
            authOTT = data["authOTT"]
        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return
        except KeyError:
            log.error("Invalid JSON data structure")
            log.debug(data)
            self.set_status(400, reason="BAD REQUEST. INVALID DATA")
            self.finish()
            return

        I = self.storage.find(stage="auth", authOTT=authOTT)

        if not I:
            log.error("Invalid or expired authOTT: {0}".format(authOTT))
            status = 408
            message = "Expired authentication request"
            userId = ""
            mpinId = ""
        else:
            authToken = I.authToken
            mpinId = authToken["mpin_id"].encode("hex")
            identity = json.loads(authToken["mpin_id"])
            userId = identity["userID"]

            if authToken.get("OTP", "0") != "0":
                OTP = authToken["OTP"]

            log.debug("authToken: {0}".format(authToken))

            if I.status:
                # Mobile authentication, status already set
                status = I.status
                message = I.message

                # get logout data
                logoutURL = data.get("logoutURL") or options.LogoutURL
                logoutData = data.get("logoutData")
                # If logoutURL is set, the mobile app will make a request to that URL
                # If logoutData is set, the request method will be POST otherwise it will be GET

                # If option waitForLoginResult is set, browserReady flag will be set on /loginResult request
                # from the RPA
                browserReady = (not options.waitForLoginResult)

                I.update(logoutData=logoutData, logoutURL=logoutURL, browserReady=browserReady)

                if not options.waitForLoginResult:
                    I.delete()
            else:
                (fail, status, reason) = verifyToken(authToken)

                aI = self.storage.find(stage="attempts", mpinId=mpinId)
                log.debug("aI: {0}".format(aI))
                attemptsCount = aI and aI.attemptsCount or 0
                log.debug("attemptsCount: {0}".format(attemptsCount))
                if attemptsCount >= options.maxInvalidLoginAttempts:
                    fail = 1

                if fail == 0:
                    # Authentication successful
                    message = "Authentication successful"
                    if aI:
                        aI.delete()
                else:
                    attemptsCount += 1
                    if aI:
                        aI.update(attemptsCount=attemptsCount)
                    else:
                        self.storage.add(stage="attempts", mpinId=mpinId, attemptsCount=attemptsCount)

                    if attemptsCount >= options.maxInvalidLoginAttempts:
                        status = 410

                    log.debug("Wrong PIN for user {0}.".format(userId))
                    message = "Wrong PIN."

                if not options.waitForLoginResult:
                    I.delete()

        returnData = {
            "userId": userId,
            "mpinId": mpinId,
            "status": status,
            "message": message
        }

        if OTP:
            returnData["OTP"] = OTP

        self.set_status(status, message)
        self.write(returnData)
        self.finish()


class LoginResultHandler(PrivateBaseHandler):

    def post(self):
        if not options.waitForLoginResult:
            self.set_status(404)
            self.finish()
            return

        try:
            data = json.loads(self.request.body)
            authOTT = data["authOTT"]
            status = data["status"]
        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return
        except KeyError:
            log.error("Invalid JSON data structure")
            log.debug(data)
            self.set_status(400, reason="BAD REQUEST. INVALID DATA")
            self.finish()
            return

        I = self.storage.find(stage="auth", authOTT=authOTT)

        if not I:
            log.error("Invalid or expired authOTT")
            self.set_status(408, reason="Invalid or expired authOTT")
            self.finish()
            return

        if int(status) != 200:
            I.update(status=status, message=data.get("message", I.message), browserReady=True)
        else:
            # Get the logout data
            # Logout data can be set on the previous /authenticate request as well.
            logoutURL = data.get("logoutURL") or I.logoutURL or options.LogoutURL
            logoutData = data.get("logoutData") or I.logoutData
            # If logoutURL is set, the mobile app will make a request to that URL
            # If logoutData is set, the request method will be POST otherwise it will be GET

            I.update(logoutData=logoutData, logoutURL=logoutURL, browserReady=True)

        I.delete()


class DynamicOptionsHandler(PrivateBaseHandler):
    @tornado.web.asynchronous
    def post(self):
        if options.dynamicOptionsURL:
            process_dynamic_options(
                DYNAMIC_OPTION_MAPPING,
                DYNAMIC_OPTION_HANDLERS,
                application=self.application)
            self.set_status(200, 'OK')
        else:
            self.set_status(403, 'Dynamic options are disabled')
        self.finish()

    def get(self):
        if options.dynamicOptionsURL:
            self.set_status(200, 'OK')
            self.write(generate_dynamic_options(DYNAMIC_OPTION_MAPPING))
        else:
            self.set_status(403, 'Dynamic options are disabled')


class MobileConfigHandler(BaseHandler):
    def get(self):
        if not options.mobileConfig:
            self.set_status(403, 'No config is available')
        elif not options.mobileUseNative:
            self.set_status(404, 'Native client is disabled')
        else:
            self.set_status(200, 'OK')
            self.write(json.dumps(options.mobileConfig))


class RPSCodeStatusHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def post(self):
        try:
            data = json.loads(self.request.body)
            data['status']
        except ValueError:
            log.error("Cannot decode body as JSON.")
            log.debug(self.request.body)
            self.set_status(400, reason="BAD REQUEST. INVALID JSON")
            self.finish()
            return
        except KeyError:
            log.error("Invalid JSON data structure")
            log.debug(data)
            self.set_status(400, reason="BAD REQUEST. INVALID DATA")
            self.finish()
            return

        mobileFlow = MobileFlow(self.application, self.storage)
        params = mobileFlow.update_app_status(data)

        self.set_status(200, 'OK')
        self.write(params)
        self.finish()


# MAIN
class Application(tornado.web.Application):
    def __init__(self):
        rpsPrefix = options.rpsPrefix.strip("/")
        handlers = [
            (r"/user/([0-9A-Fa-f]+)", UserHandler),  # POST
            (r"/{0}/user(/?[0-9A-Fa-f]*)".format(rpsPrefix), RPSUserHandler),  # PUT
            (r"/{0}/signature/([0-9A-Fa-f]+)".format(rpsPrefix), RPSSignatureHandler),  # GET
            (r"/{0}/timePermit/([0-9A-Fa-f]+)".format(rpsPrefix), RPSTimePermitHandler),  # GET
            (r"/{0}/setupDone/([0-9A-Fa-f]+)".format(rpsPrefix), RPSSetupDoneHandler),  # POST
            (r"/{0}/access".format(rpsPrefix), RPSAccessHanler),  # POST
            (r"/{0}/getAccessNumber".format(rpsPrefix), RPSGetAccessNumberHandler),  # POST
            (r"/{0}/getQrUrl".format(rpsPrefix), RPSGetQrUrlHandler),  # POST
            (r"/{0}/codeStatus".format(rpsPrefix), RPSCodeStatusHandler),  # POST
            (r"/{0}/clientSettings".format(rpsPrefix), ClientSettingsHandler),
            (r"/{0}/authenticate".format(rpsPrefix), RPSAuthenticateHandler),  # POST, for mobile login
            # Authentication
            (r"/{0}/pass1".format(rpsPrefix), Pass1Handler),
            (r"/{0}/pass2".format(rpsPrefix), Pass2Handler),

            (r"/authenticate", AuthenticateHandler),  # POST

            (r"/manage/getStackInfo", ManageGetStackInfoHandler),  # GET

            (r"/loginResult", LoginResultHandler),  # POST

            (r"/status", StatusHandler),
            (r"/service", ServiceHandler),  # GET
            (r"/dynamicOptions", DynamicOptionsHandler),  # POST, GET
            (r"/{0}/mobileConfig".format(rpsPrefix), MobileConfigHandler),  # GET
            (r"/(.*)", DefaultHandler),
        ]
        settings = {}
        super(Application, self).__init__(handlers, **settings)

        Seed.getSeed(options.EntropySources)  # Get seed value for random number generator
        self.server_secret = secrets.ServerSecret(
            Seed.seedValue,
            Keys.app_id,
            Keys.app_key)

        log.debug("Using storage: {0}".format(options.storage))
        storage_cls = get_storage_cls()
        self.storage = storage_cls(
            tornado.ioloop.IOLoop.instance(),
            "stage,mpinId",
            "stage,authOTT",
            "stage,wid",
            "stage,webOTT",
            "time_permit_id,time_permit_date"
        )


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

    Keys.getAPISettings(wait=True)

    log.info("Server starting on {0}:{1}...".format(options.address, options.port))

    http_server = Application()
    http_server.listen(options.port, options.address, xheaders=True)
    main_loop = tornado.ioloop.IOLoop.instance()
    http_server.io_loop = main_loop

    if options.autoReload:
        log.debug("Starting autoreloader")

        tornado.autoreload.watch(CONFIG_FILE)
        tornado.autoreload.start(main_loop)

    process_dynamic_options(
        DYNAMIC_OPTION_MAPPING,
        DYNAMIC_OPTION_HANDLERS,
        application=http_server,
        initial=True)

    log.info("Server started. Listening on {0}:{1}".format(options.address, options.port))
    main_loop.start()


class ServiceDaemon(Daemon):
    def run(self):
        main()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("start", "stop"):
        action = sys.argv.pop(1)
        logFile = os.path.join(BASE_DIR, "rps.log")
        pidFile = os.path.join(BASE_DIR, "rps.pid")

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
            log.error(str(e))
            sys.exit(1)
