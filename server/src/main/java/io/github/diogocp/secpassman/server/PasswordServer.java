package io.github.diogocp.secpassman.server;

import java.security.Key;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

class PasswordServer {

    private Map<Key, PasswordStore> store = new HashMap<>();

    void register(PublicKey publicKey) {
        if (store.containsKey(publicKey)) {
            throw new IllegalArgumentException("Already registered");
        }

        store.put(publicKey, new PasswordStore(publicKey));
    }

    byte[] get(Key publicKey, byte[] domain, byte[] username) {
        return store.get(publicKey).get(domain, username);
    }

    void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
        store.get(publicKey).put(domain, username, password);
    }
}
