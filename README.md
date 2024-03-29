Dependable Password Manager
===========================

Course project for *Highly Dependable Systems*, spring 2017 semester.

Build Distribution
------------------
```sh
./gradlew installDist
```

Generate and start servers
--------------------------
```sh
./start_servers F
```
where F is the maximum number of faults that can be tolerated.

Minimum 1


Client
------

```sh
client-app/build/install/client-app/bin/client-app (register|add|get) [DOMAIN USERNAME]
```

See `client-app/build/install/client-app/bin/client-app --help` for usage information.


Tests
-----
```sh
./gradlew test
```

Replay attacks
--------------
The packets were captured using [GoReplay](https://github.com/buger/goreplay).

To capture new packets run:
```sh
sudo ./gor --input-raw :(port) --output-file=(name).gor
```

To inject the packets in the network run:
```sh
sudo ./gor --input-file (name).gor --output-http="(host):(port)"
```

For example, to run the add replay attack in replay_attacks folder run:
```sh
sudo ./gor --input-file newadd_0.gor --output-http="127.0.0.1:4567"
```


