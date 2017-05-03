#!/bin/bash

# Maximum number of faults that can be tolerated
F=$1
# Total number of servers (n = 3f + 1)
N=$((3 * $F + 1))

LOWER_PORT=4567
UPPER_PORT=65535
servers="servers="
DIRECTORY="servers.tmp"


function clean_up {
    pkill -f "secpassman.server.Main"
}


if [ $(($N + $LOWER_PORT)) -le "$UPPER_PORT" ]; then
    trap clean_up SIGTERM SIGINT
    for ((i=1; i<=$N; i++)); do
        port=$(($i+$LOWER_PORT))
        if [ "$i" -lt "$N" ]; then
            servers="${servers}localhost:$port,"
        else
            servers="${servers}localhost:$port"
        fi
    done

    rm -rf "$DIRECTORY"
    mkdir -p "$DIRECTORY"
    rm -rf "certs"
    mkdir "certs"

    for ((i=1; i<=$N; i++)); do
        port=$(($i+$LOWER_PORT))
        cp -R "server/" "$DIRECTORY/server_$i/"
        cd "$DIRECTORY/server_$i"
        printf "$servers\n" > "config.properties"
        keytool -genkey -alias server -dname "CN=server_$i, OU=IST, C=PT" -keyalg RSA -validity 365 -keystore server.jks -storepass server -keypass server
        keytool -exportcert -alias server -rfc -file "../../certs/server_$i.pem" -keystore server.jks -storepass server -keypass server
        echo "\nStarting server $i"
        eval "build/install/server/bin/server $port &"
        echo "Process ID: $!"
        sleep 2
        cd "../.."
    done
    echo "Ready"
    printf "$servers\n" > "config.properties"
    wait
else
    echo "Invalid number of servers"
fi