#!/bin/bash

# Maximum number of faults that can be tolerated
F=$1
# Total number of servers (n = 3f + 1)
N=$((3 * $F + 1))

LOWER_PORT=4567
UPPER_PORT=65535
FOLDER="src/main/resources"
servers="servers="
DIRECTORY="servers.tmp"

if [ $(($N + $LOWER_PORT)) -le "$UPPER_PORT" ]; then
    for ((i=1; i<=$N; i++)); do
        port=$(($i+$LOWER_PORT))
        if [ "$i" -lt "$N" ]; then
            servers="${servers}localhost:$port,"
        else
            servers="${servers}localhost:$port"
        fi
    done
    printf "$servers\n" > "common/$FOLDER/config.properties"

    rm -r "$DIRECTORY"
    mkdir -p "$DIRECTORY"

    for ((i=1; i<=$N; i++)); do
        port=$(($i+$LOWER_PORT))
        cp -R "server/" "$DIRECTORY/server_$i/"
        (
            cd "$DIRECTORY/server_$i"
            echo "Starting server $i"
            build/install/server/bin/server "$port"
        ) &
        sleep 2
    done
    echo "Ready"
    wait
else
    echo "Invalid number of servers"
fi
