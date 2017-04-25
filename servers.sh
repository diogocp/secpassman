#!/bin/bash
#number of fault servers
F=$1
# numbers of servers = 3f + 1
N=$((3 * $F + 1))
LOWER_PORT=4567
UPPER_PORT=65535
FOLDER="src/main/resources"
servers="servers="

if [ $(($N + $LOWER_PORT)) -le "$UPPER_PORT" ]; then
	for ((i=1; i<=$N; i++)); do
		 port=$(($i+$LOWER_PORT))
		  if [ "$i" -lt "$N" ]; then
			servers="${servers}localhost:$port,"
		 else
			servers="${servers}localhost:$port"
		 fi
	done
	printf "$servers\n" >> "client-lib/$FOLDER/config.properties"

	for ((i=1; i<=$N; i++)); do
		 port=$(($i+$LOWER_PORT))
		 mkdir -p server_$i
		 cp -R "server/" "server_$i/"
		 echo "host=localhost" >> "server_$i/$FOLDER/config.properties"
		 echo "port=$port" >> "server_$i/$FOLDER/config.properties"
		 printf "$servers\n" >> "server_$i/$FOLDER/config.properties"
	done

else
	echo "Invalid number of servers"
fi

