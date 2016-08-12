# Milagro MFA Server

## General

This repository contains all the services code required to build and deploy the *Milagro MFA Server*.
This README describes the process of building and running the services on your **Ubuntu** machine.
For other Linux distributions the process would be similar, while some steps as installation of
required packages, should be adjusted for the specific platform.

## Building and Installation

### Cloning the code from the Git repository

Using standard Git client, clone the code from this repository to a local one.
The rest of this document assumes that the repository is cloned into `<milagro-mfa-server>`.
Wherever `<milagro-mfa-server>` appears, it should be replaced with the real location on your machine.

### Install with provided script

`install.sh` bash script is provided to ease the install process.
You can run it from `<milagro-mfa-server>` base directory like this
```
 > ./install.sh
```
you can provide optional argument to the script <milagro-mfa-js-client-location> where this is an absolute path of
the location `https://github.com/miracl/milagro-mfa-js-client` is downloaded.
```
 > ./install.sh <milagro-mfa-js-client-location>
```
If location provided the install script can initiate the frontend build and link the Pin Pad  in the Demo, so the demo is fully operational.

If no location is provided you should change the `mpinJSURL` yourself in demo/config.py. Which may include building the frontend and serve it from some web server.

The script is tested and should work without any issue on Ubuntu 14.04,
other versions of Ubuntu or Debian based distributions may work but is not guaranteed.

The script install some dependencies from apt-get as packages:
    * python-dev
    * python-pip
    * libffi-dev
    * git ( We use it to get Milagro crypto library)
    * cmake ( We use it to build Milagro crypto library)

Several pip packages would be installed too. They can be reviewed in \`<milagro-mfa-server>/requirements/common.txt` and `<milagro-mfa-server>/requirements/dev.txt`
`INSTALL_TYPE` environment variable is used is control  which file is used. You can use “common” or “dev” as values. “common” is used by default
The script try its best to detect virtualenv and install python packages inside one if it is founded.

The script build the needed Milagro Crypto ( Version 1.0.0 )

NOTE: While running the script if config file is already found for dta, rps or demo the user would have the option to override its content or keep it as it is.

Review the script for more details.

###Part 1: Installation
Install all dependencies needed for the services to run.

NOTE: If install.sh script is used you can skip this step

#### Installing Prerequisites

**1** Update your package manager tool
```
 > sudo apt-get update
```
**2** Install the following packages as shown below
```
 > sudo apt-get install python-dev python-pip libffi-dev
 > sudo pip install -r requirements/common.txt
```

#### Building the Milagro Crypto Libraries

Clone the [_milagro-crypto_ repository](https://github.com/miracl/milagro-crypto) 
```
> git clone https://github.com/miracl/milagro-crypto.git
``` 
Follow the instructions for your platform from the milagro-crypto [README file](https://github.com/miracl/milagro-crypto/blob/master/README.md#build-instructions).

#### Getting Credentials

Before running any Milagro Services, you should obtain your *Credentials*.
This is done with the following script:
```
 > cd <milagro-mfa-server>
 > python scripts/getCommunityCredentials.py .
```
*NOTE:* Make sure you don't miss the dot (.) at the end of the above command.<br/>
**Important:** During the above process you will be asked to enter your e-mail address. While this is not mandatory, it is recommended so we can later contact you in case of any problems with the service.
The above script will download a `credentials.json` file into the `<milagro-mfa-server>` directory.

###Part 2: Configuring the Services

The Milagro MFA Services consist of: *Distributed Trusted Authority (D-TA)* and *Relying Party Service (RPS)*.
The Web Application that integrates with the MFA in order to be able to log-in users using Milagro, is called *Relying Party Application (RPA)*.
The installation, and the source code itself include a *Demo RPA*, which should be eventually replaced by the customer specific application.
The initial configuration allows the Demo RPA and the Milagro MFA Services to be access from any machine on the local network.
Further details about configuration options might be found in the [Documentation](http://docs.miracl.com/m-pin-core-configuration).

NOTE: If install.sh script is used you can skip this step

#### Configuring the D-TA

The source includes a "default" D-TA configuration file that should serve as a template for the actual one. To configure the D-TA perform the following steps:<br/>
**1** Go to the directory `<milagro-mfa-server>/servers` and copy the `dta/config_default.py` to `dta/config.py`
```
 > cd <milagro-mfa-server>/servers
 > cp dta/config_default.py dta/config.py
```
**2** Generate a hex-encoded 8-byte (or longer) random number. You can do this with the following command:
```
 > python -c "import os; print os.urandom(8).encode('hex')"
 038b9f0756b2a2c4
```
**3** Using `vi` or other editor, edit the `dta/config.py` file<br/>
**4** Change the `salt` parameter, setting its value to the random value that was just generated:
```
salt = "038b9f0756b2a2c4"
```
**5** Add/change the `credentialsFile` parameter, specifying the location for the credential file that was previously obtained:
```
credentialsFile = "<milagro-mfa-server>/credentials.json"
```
**6** Change the value of the `backup_file` parameter to the path to file where the master secret will be backed up.<br/>
```
backup_file = "<milagro-mfa-server>/backup_dta.json"
```
**7** Change the value of the `passphrase` parameter as well. You might generate a random string for it as well, or write some phrase of your own.<br/>
**8** Save the file and exit the editor

#### Configuring the RPS

The source includes a "default" RPS configuration file that should serve as a template for the actual one. To configure the RPS perform the following steps:<br/>
**1** Go to the directory `<milagro-mfa-server>/servers` and copy the `rps/config_default.py` to `rps/config.py`
```
 > cd <milagro-mfa-server>/servers
 > cp rps/config_default.py rps/config.py
```
**2** Using `vi` or other editor, edit the `rps/config.py` file<br/>
**3** Add/change the `credentialsFile` parameter, specifying the location for the credential file that was previously obtained:
```
credentialsFile = "<milagro-mfa-server>/credentials.json"
```
**4** Save the file and exit the editor

#### Configuring the Demo RPA

The source includes a "default" Demo RPA configuration file. To configure the Demo RPA perform the following steps:<br/>
**1** Go to the directory `<milagro-mfa-server>/servers` and copy the `demo/config_default.py` to `demo/config.py`
```
 > cd <milagro-mfa-server>/servers
 > cp demo/config_default.py demo/config.py
```
**2** Generate a base64-encoded 64-byte (or longer) random number. You can do this with the following command:
```
 > python -c "import os; print os.urandom(64).encode('base64')"
 nju31zsOvxg+a0U4aCVrIOXf/VH/GC7/6oWK+8eEBM3OzNbbGOaL0mtne2g68O78MDYEz8fQz4MG
 /7irix5Gfg==
```
**3** Using `vi` or other editor, edit the `demo/config.py` file<br/>
**4** Change the `cookieSecret` parameter, setting its value to the random value that was just generated:
```
cookieSecret = "nju31zsOvxg+a0U4aCVrIOXf/VH/GC7/6oWK+8eEBM3OzNbbGOaL0mtne2g68O78MDYEz8fQz4MG/7irix5Gfg=="
```
**5** Change the `mpinJSURL` to the URL where the PIN Pad is served from. For instance:
```
mpinJSURL = "http://mpin.miracl.com/v4/mpin.js"
```
**6** Save the file and exit the editor

###Part 3: Running and Testing the Services

For development purposes you might run the services from command line. Open 3 terminals and set the following two environment variables as shown below:
```
export PYTHONPATH=<milagro-mfa-server>/lib:/usr/local/lib/python2.7/site-packages
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```
To run the services, perform the following commands, each in separate terminal:
```
 > python servers/dta/dta.py
```
```
 > python servers/rps/rps.py
```
```
 > python servers/demo/mpinDemo.py
```
For more automated execution, you might need to write start/stop scripts in `/etc/init.d`

Using the following commands, you can test whether the services are running fine
- **D-TA**:
```
> curl http://127.0.0.1:8001/status
{"service_name": "D-TA server", "message": "OK", "startTime": ["2015-03-13T15:09:41Z"]}
```
- **RPS**:
```
> curl http://127.0.0.1:8011/status
{"message": "active", "version": "0.3"}
> curl http://127.0.0.1:8011/rps/clientSettings
{"requestOTP": false, "mpinAuthServerURL": "/rps", "timePermitsURL": "http://127.0.0.1:8011/rps/timePermit", "useWebSocket": false, "setDeviceName": false, "seedValue": "3cd2a085a056eb4748ed0ff9dd1b0e298a7bfbb59e96f75fb2228ab22f9b55133894d36edec166d5eb8c2941c0ddf16aea70f1fa392a41486c463c715e5b4a696c0bed2d264011852f23a33172a19636da27a5df90d49bcde5c8a36bb0c5cb1abe67345d", "accessNumberDigits": 7, "accessNumberURL": "http://127.0.0.1:8011/rps/accessnumber", "setupDoneURL": "http://127.0.0.1:8011/rps/setupDone", "timePermitsStorageURL": "https://timepermits.certivox.net", "authenticateURL": "/mpinAuthenticate", "certivoxURL": "https://community-api.certivox.net/v3/", "registerURL": "http://127.0.0.1:8011/rps/user", "appID": "a2fcdf24c98e11e4b69d02547e1fd4a1", "cSum": 1, "signatureURL": "http://127.0.0.1:8011/rps/signature", "getAccessNumberURL": "http://127.0.0.1:8011/rps/getAccessNumber", "mobileAuthenticateURL": "http://127.0.0.1:8011/rps/authenticate"}
```
- **Demo**:
```
> curl http://127.0.0.1:8005
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    . . .
</head>
<body>
</body>
    . . .
</html>
```
Finally, open a browser on any machine that has network access to the machine on which the Milagro MFA Services are running. Browse to `http://<mpin-server-ip>:8005`.
You should see the Demo application loaded.

For further details on the Milagro MFA Server Configuration, please see the [Milagro Documentation](http://docs.milagro.io)
