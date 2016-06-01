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
