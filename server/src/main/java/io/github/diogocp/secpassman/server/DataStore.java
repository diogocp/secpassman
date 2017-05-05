package io.github.diogocp.secpassman.server;

import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

class DataStore {

    private final Map<PublicKey, User> users;

    DataStore() {
        users = new ConcurrentHashMap<>();
    }

    boolean containsUser(PublicKey publicKey) {
        return users.containsKey(publicKey);
    }

    void registerUser(PublicKey publicKey) {
        users.put(publicKey, new User(publicKey));
    }

    User getUser(PublicKey publicKey) {
        return users.get(publicKey);
    }

    void putPassword(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        users.get(publicKey).putPassword(domain, username, password);
    }

    byte[] getPassword(PublicKey publicKey, byte[] domain, byte[] username) {
        return users.get(publicKey).getPassword(domain, username);
    }
}
