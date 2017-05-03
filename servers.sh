#!/bin/bash

# Maximum number of faults that can be tolerated
F=$1
# Total number of servers (n = 3f + 1)
N=$((3 * $F + 1))

LOWER_PORT=4567
UPPER_PORT=65535
servers="servers="
DIRECTORY="servers.tmp"


#keytool -genkey -alias teste3 -dname "CN=server3, OU=IST, C=PT" -keyalg RSA -validity 365 -keystore xptokeystore.jks -storepass 123456 -keypass 123456
#keytool -exportcert -alias server3 -rfc -file server3.pem -keystore testekeys.jks -keypass 123456

function clean_up {
    pkill -f "secpassman.server.Main"
}

# function gen_certs {
#     keytool -genkey -alias server -dname "CN=$1, OU=IST, C=PT" -keyalg RSA -validity 365 -keystore server.jks -storepass server -keypass server
#     keytool -exportcert -alias server -rfc -file $1.pem -keystore server.jks -keypass server
# }

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