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

from setuptools import setup, find_packages

setup(
    name="M-Pin Backend",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'cffi==0.9.0',
        'pbkdf2==1.3',
        'python-dateutil==2.4.2',
        'redis==2.10.3',
        'tornado==4.1',
    ],
    author="CertiVox",
    author_email="support@miracl.com",
    description="M-Pin Backend services",
    url="https://github.com/CertiVox/mpin-backend",
)
