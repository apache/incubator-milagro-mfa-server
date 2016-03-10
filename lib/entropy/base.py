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


class EntropySourceBase(object):
    entropyDescription = "Entropy source base"

    def __init__(self, bytesNeeded, logger=None, **kwargs):
        self.bytesNeeded = bytesNeeded
        self.logger = logger
        for key, value in kwargs.items():
            setattr(self, key, value)

    def _getEntropy(self):
        raise NotImplementedError

    def getEntropy(self):
        _bytes = b""
        if self.logger:
            self.logger.info("Getting entropy from {0}...".format(self.entropyDescription))

        while len(_bytes) < self.bytesNeeded:
            _bytes += self._getEntropy()

        _result = _bytes[:self.bytesNeeded]

        if self.logger:
            self.logger.debug("Entropy from {0}: {1}".format(self.entropyDescription, _result.encode("hex")))

        return _result
