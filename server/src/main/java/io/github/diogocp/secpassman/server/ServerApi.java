package io.github.diogocp.secpassman.server;

import java.security.KeyPair;
import java.security.PublicKey;

class ServerApi {

    public final KeyPair keyPair;
    private final DataStore dataStore;

    ServerApi(KeyPair keyPair, DataStore dataStore) {
        this.keyPair = keyPair;
        this.dataStore = dataStore;
    }

    void register(PublicKey publicKey) {
        dataStore.registerUser(publicKey);
    }

    byte[] get(PublicKey publicKey, byte[] domain, byte[] username) {
        return dataStore.getPassword(publicKey, domain, username);
    }

    void put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        dataStore.putPassword(publicKey, domain, username, password);
    }
}
