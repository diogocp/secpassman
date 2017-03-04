Dependable Password Manager
===========================

Course project for *Highly Dependable Systems*, spring 2017 semester.

Server
------

```sh
./gradlew :server:run
```

The server listens on port 4567.


Client
------

```sh
./gradlew :client-app:installDist
client-app/build/install/client-app/bin/client-app (register|add|get) [DOMAIN USERNAME]
```

See `client-app/build/install/client-app/bin/client-app --help` for usage information.
