#!/usr/bin/env bash

BASE_DIR=$(pwd)

INSTALL_TYPE=${INSTALL_TYPE:-"common"}

function install_dependencies {
    echo "Install needed packages"

    # Update packages cache
    sudo apt-get update

    # Install needed packages
    sudo apt-get install python-dev python-pip libffi-dev cmake

    # Install the required packages
    python -c 'import sys; print hasattr(sys, "real_prefix")' 2>/dev/null && VIRTUALENV=1 || VIRTUALENV=0
    if [[ $VIRTUALENV == 1 ]]
    then
        # If in virtualenv use the local provided pip
        # We assume that activation script is used and pip as command points to virtualenv pip
        pip install -r "requirements/$INSTALL_TYPE.txt"
    else
        # If we are not in virtualenv we just install global
        sudo pip install -r "requirements/$INSTALL_TYPE.txt"
    fi
}

function get_crypto {
    echo "Get Milagro Crypto Libraries"
    mkdir -p install
    cd install
    git clone https://github.com/miracl/milagro-crypto.git

    cd milagro-crypto
    git checkout tags/1.0.0
}

function build_crypto {
    echo "Build Milagro crypto library"

    mkdir Release
    cd Release
    cmake ..
    make
    make test
    sudo make install
}

function get_credentials {
    cd $BASE_DIR
    python scripts/getCommunityCredentials.py .
}

function build_frontend {
    echo "TODO build frontend js"
    # TODO build and set the builded frontend here

    mkdir -p $BASE_DIR/servers/demo/public/js
    cd $BASE_DIR/servers/demo/public/js
}

function get_dependencies {
    install_dependencies

    get_crypto

    build_crypto

    get_credentials

    build_frontend
}

# Configure services

function configure_dta {
    echo "Configure DTA"

    cd $BASE_DIR/servers/dta
    cp config_default.py config.py

    CONFIG_FILE=$(pwd)/config.py
    SALT=$(python -c "import os; print os.urandom(8).encode('hex')")
    PASSPHRASE=$(python -c "import os; print os.urandom(8).encode('hex')")

    CREDENTIALSFILE="$BASE_DIR/credentials.json"
    BACKUP_FILE="$BASE_DIR/backup_dta.json"

    sed -i "s/\(%SALT%\)/$SALT/" $CONFIG_FILE
    sed -i "s/\(%PASSPHRASE%\)/$PASSPHRASE/" $CONFIG_FILE
    sed -i "s#\(%CREDENTIALSFILE%\)#$CREDENTIALSFILE#" $CONFIG_FILE
    sed -i "s#\(%BACKUP_FILE%\)#$BACKUP_FILE#" $CONFIG_FILE
}

function configure_rps {
    echo "Configure RPS"

    cd $BASE_DIR/servers/rps
    cp config_default.py config.py

    CONFIG_FILE=$(pwd)/config.py
    CREDENTIALSFILE="$BASE_DIR/credentials.json"

    sed -i "s#\(%CREDENTIALSFILE%\)#$CREDENTIALSFILE#" $CONFIG_FILE
}

function configure_demo {
    echo "Configure Demo RPA"

    cd $BASE_DIR/servers/demo
    cp config_default.py config.py

    CONFIG_FILE=$(pwd)/config.py
    # We need to remove new line, sed does not like it
    COOKIESECRET=$(python -c "import os; print os.urandom(64).encode('base64').replace(\"\n\", '')")

    # mpin.js can be downloaded or copied/linked from localy build milagro-js-client
    MPINJSURL="/public/mpin.js"

    sed -i "s#\(%COOKIESECRET%\)#$COOKIESECRET#" $CONFIG_FILE
    sed -i "s#\(%MPINJSURL%\)#$MPINJSURL#" $CONFIG_FILE

}

function run_instructions {
    echo "
    For development purposes you might run the services from command line.
    Open 3 terminals and set the following two environment variables as shown below:

    export PYTHONPATH=<mpin-backend>/lib:/usr/local/lib/python2.7/site-packages
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    To run the services, perform the following commands, each in separate terminal:

     > python dta/dta.py
     > python rps/rps.py
     > python demo/mpinDemo.py
    For more automated execution, you might need to write start/stop scripts in /etc/init.d
    "
}

function configure_services {
    echo "Configure the services"

    configure_dta

    configure_rps

    configure_demo

    run_instructions
}

get_dependencies

configure_services
