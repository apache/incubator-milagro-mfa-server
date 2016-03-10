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

# Mailer module, send mail from a separate thread
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from tornado import template

smtpServer = ""
smtpPort = 0
senderAddress = ""
useTLS = False


# Render templates
def render_template(template_name, **kwargs):
    loader = template.Loader(os.path.dirname(os.path.realpath(__file__)) + "/templates")
    t = loader.load(template_name)
    return t.generate(**kwargs)


# Initialize the mailer parameters
def setup(smtpserver, smtpport, senderaddress, usetls):
    global smtpServer, smtpPort, senderAddress, useTLS
    smtpServer = smtpserver
    smtpPort = smtpport
    senderAddress = senderaddress
    useTLS = usetls


# The actual mail sending routine (which should be ran from sendActivationEmail() in a separate thread so that Tornado is not blocked)
def mailerThread(recipientAddress, subject, deviceName, validationURL, user=None, password=None):
    if not smtpServer:
        return
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = senderAddress
    msg['To'] = recipientAddress

    # Text version (in case the mail client does not like the HTML part).
    mailText = render_template('activation_email.txt', validationURL=validationURL)

    # HTML version
    mailHTML = render_template('activation_email.html', validationURL=validationURL)

    mailPartText = MIMEText(mailText, 'plain')
    mailPartHTML = MIMEText(mailHTML, 'html')
    msg.attach(mailPartText)
    msg.attach(mailPartHTML)

    sender = smtplib.SMTP(smtpServer, smtpPort)

    if useTLS:
        sender.starttls()
        sender.ehlo()

    if user:
        sender.login(user, password)

    sender.sendmail(senderAddress, recipientAddress, msg.as_string())
    sender.quit()


def sendActivationEmail(recipientAddress, subject, deviceName, validationURL, user=None, password=None):
    thread = Thread(target=mailerThread, args=(recipientAddress, subject, deviceName, validationURL, user, password))
    thread.start()
