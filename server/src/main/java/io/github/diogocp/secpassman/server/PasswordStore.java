package io.github.diogocp.secpassman.server;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import java.security.PublicKey;
import java.util.Base64;

class PasswordStore implements java.io.Serializable {

    private static final Base64.Encoder base64 = Base64.getEncoder();

    private PublicKey publicKey;
    private long version;
    private Table<String, String, byte[]> store;

    PasswordStore(PublicKey publicKey) {
        this.publicKey = publicKey;
        version = 1;
        store = HashBasedTable.create();
    }

    byte[] get(byte[] domain, byte[] username) {
        return store.get(base64.encodeToString(domain), base64.encodeToString(username));
    }

    void put(byte[] domain, byte[] username, byte[] password) {
        store.put(base64.encodeToString(domain), base64.encodeToString(username), password);
        version++;
    }
}
