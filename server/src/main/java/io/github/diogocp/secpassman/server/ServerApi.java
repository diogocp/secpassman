package io.github.diogocp.secpassman.server;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

class ServerApi {

    private Map<PublicKey, User> users = new HashMap<>();

    void register(PublicKey publicKey) {
        if (users.containsKey(publicKey)) {
            throw new IllegalArgumentException("Already registered");
        }

        users.put(publicKey, new User(publicKey));
    }

    byte[] get(PublicKey publicKey, byte[] domain, byte[] username) {
        return users.get(publicKey).getPassword(domain, username);
    }

    void put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        users.get(publicKey).putPassword(domain, username, password);
    }
}
