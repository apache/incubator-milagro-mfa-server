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
import time
from pprint import pformat
from urlparse import urlparse

import tornado.httpclient
from tornado.log import app_log as log

proxies = {}

# Time for which signatures are valid
SIGNATURE_EXPIRES_OFFSET_SECONDS = 60


class Keys(object):
    app_id = "\0" * 16
    app_key = ""
    api_url = ""
    timePermitsStorageURL = ""
    managementConsoleURL = ""

    @staticmethod
    def loadFromFile(keysfile):
        try:
            with open(keysfile, "r") as keysfile:
                data = json.loads(keysfile.read())
        except IOError:
            log.error("Cannot load keys file!")
            return False
        except ValueError:
            log.error("Keys file contains invalid json!")
            return False

        try:
            Keys.app_id = str(data["app_id"])
            Keys.app_key = str(data["app_key"])
            Keys.api_url = str(data["api_url"]).rstrip("/") + "/"
        except KeyError:
            log.error("Invalid keys file. app_id, app_key and api_url fields are required!")
            return False

        if 'certivox_server_secret' in data:
            Keys.certivox_server_secret = data['certivox_server_secret']

        return True

    @staticmethod
    def certivoxServer():
        return Keys.api_url

    @staticmethod
    def timeServer():
        return "{0}time".format(Keys.api_url)

    @staticmethod
    def _getAPISettings():

        apiSettingsURL = "{0}apiSettings".format(Keys.api_url)
        log.debug("Getting API settings from {0}".format(apiSettingsURL))

        httpClient = tornado.httpclient.HTTPClient()
        apiResponse = httpClient.fetch(apiSettingsURL, **fetchConfig(apiSettingsURL))
        apiData = json.loads(apiResponse.body)
        Keys.timePermitsStorageURL = apiData.get("timePermitsStorageURL", "")
        Keys.managementConsoleURL = apiData.get("managementConsoleURL", "")
        log.debug("timpePermitsStorageURL = {0}; managementConsoleURL = {1}".format(Keys.timePermitsStorageURL, Keys.managementConsoleURL))

    @staticmethod
    def getAPISettings(wait=False):
        seconds = 5
        while True:
            try:
                Keys._getAPISettings()
                break
            except Exception as E:
                log.error(E)
                log.error("Unable to get data from API server. Retrying in {0} seconds".format(seconds))
                if not wait:
                    break
                time.sleep(seconds)


class Applications(object):
    """
    Load the file that contains the list of applications
    Provide ability to add and remove apps
    Provide ability to save applications to file
    """

    def __init__(self, filename=None):
        self.filename = 'apps.json'
        if not filename:
            self.appData = {}
        else:
            data = json.load(open(filename, "r"))
            self.appData = data['appData']

    def addApp(self, app_id, app_key, app_url):
        '''Add applications to memory and update file'''
        self.appData[app_id] = [app_key, app_url]
        self.writeFile()

    def deleteApp(self, app_id):
        '''Delete application from memory and update file'''
        del self.appData[app_id]
        self.writeFile()

    def writeFile(self):
        '''Write data in JSON format to file'''
        data = {'appData': self.appData}
        json.dump(data, open(self.filename, "w"))

    def __repr__(self):
        data = {}
        data['appData'] = self.appData
        return str(data)


def detectProxy():
    # Detect proxy settings for http and https from the environment
    # Uses http_proxy and https_proxy environment variables

    httpProxy = os.environ.get("HTTP_PROXY", os.environ.get("http_proxy", ""))
    httpsProxy = os.environ.get("HTTPS_PROXY", os.environ.get("https_proxy", ""))
    noProxy = os.environ.get("NO_PROXY", os.environ.get("no_proxy", ""))

    if httpProxy:
        u = urlparse(httpProxy)
        proxies["http"] = {
            "proxy_host": u.hostname or None,
            "proxy_port": u.port or None,
            "proxy_username": u.username or None,
            "proxy_password": u.password or None
        }

    if httpsProxy:
        u = urlparse(httpsProxy)
        proxies["https"] = {
            "proxy_host": u.hostname or None,
            "proxy_port": u.port or None,
            "proxy_username": u.username or None,
            "proxy_password": u.password or None
        }

    if httpProxy or httpsProxy:
        tornado.httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

    if noProxy:
        proxies["noProxy"] = noProxy.split(",")


def fetchConfig(url):
    # Get fetch config settings for httpclient for proxy
    u = urlparse(url)
    if u.scheme in proxies:
        if u.hostname not in proxies.get("noProxy", []):
            return proxies[u.scheme]

    return {}


class Time(object):
    monthNames = ["Jan.", "Feb.", "Mar.", "Apr.", "May", "June", "July", "Aug.", "Sept.", "Oct.", "Nov.", "Dec."]

    timeOffset = datetime.timedelta()

    @staticmethod
    def syncedNow(**kwards):
        if kwards:
            return datetime.datetime.utcnow() + Time.timeOffset + datetime.timedelta(**kwards)
        else:
            return datetime.datetime.utcnow() + Time.timeOffset

    @staticmethod
    def Now(**kwards):
        if kwards:
            return datetime.datetime.utcnow() + datetime.timedelta(**kwards)
        else:
            return datetime.datetime.utcnow()

    @staticmethod
    def DateTimeToISO(dt):
        return dt.isoformat("T").split(".")[0] + "Z"

    @staticmethod
    def syncedISO(**kwards):
        return Time.syncedNow(**kwards).isoformat("T").split(".")[0] + "Z"

    @staticmethod
    def ISO(**kwards):
        return Time.Now(**kwards).isoformat("T").split(".")[0] + "Z"

    @staticmethod
    def ISOtoDateTime(isoDate):
        isoDate = isoDate.split(".")[0].replace(" ", "T")
        return datetime.datetime.strptime(isoDate.split("Z")[0], "%Y-%m-%dT%H:%M:%S")

    @staticmethod
    def DateTimetoHuman(d):
        return d.strftime("%H:%M GMT, {0} %d, %Y".format(Time.monthNames[d.month - 1]))

    @staticmethod
    def _getTime(timeServer=None):
        if not timeServer:
            timeServer = Keys.timeServer()

        log.info("Getting time from {0}".format(timeServer))
        httpClient = tornado.httpclient.HTTPClient()
        timeResponse = httpClient.fetch(timeServer, **fetchConfig(timeServer))
        timeData = json.loads(timeResponse.body)
        certivoxClock = timeData["Time"].replace(" ", "T")
        certivoxTime = datetime.datetime.strptime(certivoxClock[:-1], '%Y-%m-%dT%H:%M:%S')
        log.debug("CertiVox Time: %s" % certivoxTime)
        log.debug("Local system time: %s" % datetime.datetime.utcnow())
        Time.timeOffset = certivoxTime - datetime.datetime.utcnow()
        log.info("Synced time: %s" % (datetime.datetime.utcnow() + Time.timeOffset))

    @staticmethod
    def getTime(wait=False, timeServer=None):
        seconds = 5
        while True:
            try:
                Time._getTime(timeServer)
                break
            except Exception as E:
                log.error(E)
                log.error("Unable to get data from the time server. Retrying in {0} seconds".format(seconds))
                if not wait:
                    break
                time.sleep(seconds)

    @staticmethod
    def DateTimetoEpoch(d):
        return int(time.mktime(d.timetuple()) * 1000)


class Seed(object):
    seedValue = None

    @staticmethod
    def _getSeed(entropySources=""):
        sources = entropySources.split(",")

        totalSize = 100
        totalEntropy = ""
        for source in sources:
            if not source.strip():
                continue
            s = source.split(":")
            moduleName = s[0]
            eSize = len(s) > 1 and int(s[1]) or totalSize

            E = __import__("entropy.{0}".format(moduleName), globals(), locals(), ["EntropySource"]).EntropySource
            totalEntropy += E(eSize, logger=log).getEntropy()
            if len(totalEntropy) / 2 > totalSize:
                break

        if len(totalEntropy) < totalSize:
            log.error("Seed value size is too small. Needed: {0} bytes, Got: {1} bytes.".format(totalSize, len(totalEntropy)))
            raise Exception("Seed value size is too small. Check your configuration.")

        Seed.seedValue = totalEntropy
        log.debug("Seed.seedValue: %s" % Seed.seedValue.encode("hex"))
        log.debug("Seed.seedValue length: %d" % len(Seed.seedValue))

    @staticmethod
    def getSeed(entropySources=""):
        seconds = 5
        while True:
            try:
                Seed._getSeed(entropySources)
                break
            except Exception as E:
                log.error(E)
                log.error("Unable to get seed. Retrying in {0} seconds".format(seconds))
                time.sleep(seconds)


def signMessage(message, key):
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()


def verifySignature(message, signature, key, expiresStr=None):
    """
        Verify the signature and also that the timestamp has not expired. If expiresStr is None, the timestamp is not checked.

        Returns:
            Valid - bool

    """
    nowTime = Time.syncedNow()
    try:
        expiresTime = expiresStr and Time.ISOtoDateTime(expiresStr) or nowTime
        hmacExpected = hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()
        hmac1 = hmac.new(key, signature, hashlib.sha256).hexdigest()
        hmac2 = hmac.new(key, hmacExpected, hashlib.sha256).hexdigest()
        if hmac1 != hmac2:
            reason = "Invalid signature"
            valid = False
            code = 401
        elif nowTime > expiresTime:
            reason = "Request expired"
            valid = False
            code = 408
        else:
            reason = "Valid signature"
            valid = True
            code = 200

    except Exception as E:
        valid = False
        reason = "Error verifying message. {0}".format(E)
        code = 500

    if not valid:
        debugData = {
            "reason": reason,
            "message": message,
            "key": key,
            "signature": signature,
            "hmacExpected": hmacExpected,
            "expiresStr": expiresStr,
            "expiresTime": Time.DateTimeToISO(expiresTime),
            "nowTime": Time.DateTimeToISO(nowTime)
        }

        log.debug("verifyMessage: {0}".format(pformat(debugData)))

    return valid, reason, code


def getLogLevel(logLevel):
    return (type(logLevel) == int) and logLevel or {
        'CRITICAL': 50,
        'ERROR': 40,
        'WARN': 30,
        'INFO': 20,
        'DEBUG': 10,
        'ALL': 0,
    }.get(logLevel.upper(), 20)
