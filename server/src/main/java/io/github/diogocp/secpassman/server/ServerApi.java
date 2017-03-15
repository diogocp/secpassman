package io.github.diogocp.secpassman.server;

import java.security.PublicKey;

class ServerApi {

    private final DataStore dataStore;

    ServerApi(DataStore dataStore) {
        this.dataStore = dataStore;
    }

    void register(PublicKey publicKey) {
        if (dataStore.containsUser(publicKey)) {
            throw new IllegalArgumentException("Already registered");
        }

        dataStore.registerUser(publicKey);
    }

    byte[] get(PublicKey publicKey, byte[] domain, byte[] username) {
        return dataStore.getPassword(publicKey, domain, username);
    }

    void put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        dataStore.putPassword(publicKey, domain, username, password);
    }
}
