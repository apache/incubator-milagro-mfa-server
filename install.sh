#!/usr/bin/env bash

BASE_DIR=$(pwd)

# Specify where the frontend repo is located
FRONTEND_LOCATION=${FRONTEND_LOCATION:-$1}

INSTALL_TYPE=${INSTALL_TYPE:-"common"}

function install_dependencies {
    echo "Install needed packages"

    # Update packages cache
    sudo apt-get update

    # Install needed packages
    sudo apt-get install python-dev python-pip libffi-dev git cmake

    # Install the required packages
    VIRTUALENV=$(python -c 'import sys; print hasattr(sys, "real_prefix")' 2>/dev/null)
    if [[ $VIRTUALENV ]]
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
    cd install || exit
    git clone https://github.com/miracl/milagro-crypto.git

    cd milagro-crypto || exit
    git checkout tags/1.0.0
}

function build_crypto {
    echo "Build Milagro crypto library"

    mkdir Release
    cd Release || exit
    cmake ..
    make
    make test
    sudo make install
}

function get_credentials {
    cd "$BASE_DIR" || exit
    python scripts/getCommunityCredentials.py .
}

function build_frontend {
    echo "build frontend js"

    # Go to frontend code location
    cd "$FRONTEND_LOCATION" || exit
    # run frontend build script
    ./build.sh

    # Create the needed directory and link the frontend
    cd "$BASE_DIR/servers/demo/public/" || exit

    ln -sf "$FRONTEND_LOCATION/build/out/browser" mpin
}

function get_dependencies {
    install_dependencies

    get_crypto

    build_crypto

    get_credentials

}

# Configure services

function configure_dta {
    echo "Configure DTA"

    cd "$BASE_DIR/servers/dta" || exit

    CONFIGURE=1
    if [ -f config.py ]
    then
        echo "NOTE: Config file for DTA already exist"
        read -p "Do you want to override it (y/n)?" choice
        case "$choice" in 
          y|Y ) echo "yes"; CONFIGURE=1;;
          n|N ) echo "no"; CONFIGURE=0;;
          * ) echo "invalid";;
        esac
    fi

    if [ $CONFIGURE ]
    then
        cp config_default.py config.py
        CONFIG_FILE=$(pwd)/config.py
        SALT=$(python -c "import os; print os.urandom(8).encode('hex')")
        PASSPHRASE=$(python -c "import os; print os.urandom(8).encode('hex')")

        CREDENTIALSFILE="$BASE_DIR/credentials.json"
        BACKUP_FILE="$BASE_DIR/backup_dta.json"
        rm -f "$BASE_DIR/backup_dta.json"

        sed -i "s/\(%SALT%\)/$SALT/" "$CONFIG_FILE"
        sed -i "s/\(%PASSPHRASE%\)/$PASSPHRASE/" "$CONFIG_FILE"
        sed -i "s#\(%CREDENTIALSFILE%\)#$CREDENTIALSFILE#" "$CONFIG_FILE"
        sed -i "s#\(%BACKUP_FILE%\)#$BACKUP_FILE#" "$CONFIG_FILE"
    fi
}

function configure_rps {
    echo "Configure RPS"

    cd "$BASE_DIR/servers/rps" || exit

    CONFIGURE=1
    if [ -f config.py ]
    then
        echo "NOTE: Config file for DTA already exist"
        read -p "Do you want to override it (y/n)?" choice
        case "$choice" in 
          y|Y ) echo "yes"; CONFIGURE=1;;
          n|N ) echo "no"; CONFIGURE=0;;
          * ) echo "invalid";;
        esac
    fi

    if [ $CONFIGURE ]
    then
        cp config_default.py config.py

        CONFIG_FILE=$(pwd)/config.py
        CREDENTIALSFILE="$BASE_DIR/credentials.json"

        sed -i "s#\(%CREDENTIALSFILE%\)#$CREDENTIALSFILE#" "$CONFIG_FILE"
    fi
}

function configure_demo {
    echo "Configure Demo RPA"

    cd "$BASE_DIR/servers/demo" || exit

    CONFIGURE=1
    if [ -f config.py ]
    then
        echo "NOTE: Config file for DTA already exist"
        read -p "Do you want to override it (y/n)?" choice
        case "$choice" in 
          y|Y ) echo "yes"; CONFIGURE=1;;
          n|N ) echo "no"; CONFIGURE=0;;
          * ) echo "invalid";;
        esac
    fi

    if [ $CONFIGURE ]
    then
        cp config_default.py config.py

        CONFIG_FILE=$(pwd)/config.py
        # We need to remove new line, sed does not like it
        COOKIESECRET=$(python -c "import os; print os.urandom(64).encode('base64').replace(\"\n\", '')")

        sed -i "s#\(%COOKIESECRET%\)#$COOKIESECRET#" "$CONFIG_FILE"

        if [ "$FRONTEND_LOCATION" ]
        then
            build_frontend

            # mpin.js can be downloaded or copied/linked from localy build milagro-js-client
            MPINJSURL="/public/mpin/mpin.js"
            sed -i "s#\(%MPINJSURL%\)#$MPINJSURL#" "$CONFIG_FILE"
        else
            echo $'\n'
            echo "NOTE: No location for the frontend provided you will need to configure %MPINJSURL% yourself"
        fi;
    fi
}

function run_instructions {
    echo "
    For development purposes you might run the services from command line.
    Open 3 terminals and set the following two environment variables as shown below:

    export PYTHONPATH=<mpin-backend>/lib:/usr/local/lib/python2.7/site-packages
    export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib
    To run the services, perform the following commands, each in separate terminal:

     > python servers/dta/dta.py
     > python servers/rps/rps.py
     > python servers/demo/mpinDemo.py
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
