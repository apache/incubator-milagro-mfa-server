import uuid
import datetime

from tornado.log import app_log as log
from tornado.options import options

from mpin_utils import secrets
from mpin_utils.common import (
    Time,
)


class MobileFlow:
    """  Holds Bussines logic for the Mobile flow """

    def __init__(self, application, storage):
        self.application = application
        self.storage = storage

    def generate_wid(self):
        # Generate request for MPinWIDServer for WID
        wId = uuid.uuid4().hex

        while wId is None or (self.storage.find(stage="auth", wid=wId)):
            if wId is None:
                log.debug("WebId is None".format(wId))
            else:
                log.debug("WebId {0} already exists. Generating a new one".format(wId))

            wId = uuid.uuid4().hex
            log.debug("New webId generated: {0}." .format(wId))

        return wId

    def generate_qr(self, wId):
        webOTT = secrets.generate_ott(options.OTTLength, self.application.server_secret.rng, "hex")

        nowTime = Time.syncedNow()
        expirePinPadTime = nowTime + datetime.timedelta(seconds=options.accessNumberExpireSeconds)
        expireTime = expirePinPadTime + datetime.timedelta(seconds=options.accessNumberExtendValiditySeconds)

        self.storage.add(stage="auth", expire_time=expireTime, webOTT=webOTT, wid=wId)

        qrUrl = options.rpsBaseURL + "#" + wId

        params = {
            "ttlSeconds": options.accessNumberExpireSeconds,
            "qrUrl": qrUrl,
            "webOTT": webOTT,
            "localTimeStart": Time.DateTimetoEpoch(nowTime),
            "localTimeEnd": Time.DateTimetoEpoch(expirePinPadTime)
        }

        return params

    def update_app_status(self, data):
        mobile_status = data.get('status')
        params = {
            'Status': 'OK'
        }

        # Keyfind
        keyAuth = self.storage.find(stage="auth", wid=data.get('wid'))
        if not keyAuth:
            return params

        userId = data.get('userId')

        keyAuth.update(mobile_status=mobile_status, userId=userId)

        if mobile_status == "wid":
            params = {
                'PrerollId': "",  # We don't use it at the moment
                'AppName': options.serviceName,
                'AppLogoUrl': options.serviceIconUrl,
            }

        return params

    def get_app_status(self, webOTT):
        params = {
            'status':      "new",
            'statusCode':  0,
            'userId':      "",
            'redirectURL': "",
            'authOTT': ""
        }

        I = self.storage.find(stage="auth", webOTT=webOTT)
        if not I:
            log.debug("Cannot find webOTT: {0}".format(webOTT))
            params['status'] = 'expired'
            return params

        if I.mobile_status:
            params['status'] = I.mobile_status

        if I.mobile_status == 'user' and I.userId:
            params['userId'] = I.userId

        authOTT = I.authOTT
        if authOTT and (str(I.status) == "200"):
            params['status'] = 'authenticate'
            params['authOTT'] = authOTT

        return params
