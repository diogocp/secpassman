package io.github.diogocp.secpassman.server;

import com.google.common.io.BaseEncoding;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

class PasswordServer {

    private Map<Key, PasswordStore> store = new HashMap<>();

    void register(Key publicKey) {
        if (store.containsKey(publicKey)) {
            throw new IllegalArgumentException("Already registered");
        }

        store.put(publicKey, new PasswordStore(publicKey));
    }

    String get(Key publicKey, String domain, String username) {
        return store.get(publicKey).get(domain, username);
    }

    void put(Key publicKey, String domain, String username, String password) {
        store.get(publicKey).put(domain, username, password);
    }

    byte[] get(Key publicKey, byte[] domain, byte[] username) {
        return BaseEncoding.base16().decode(
            get(publicKey,
                BaseEncoding.base16().encode(domain),
                BaseEncoding.base16().encode(username)
            )
        );
    }

    void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
        put(
            publicKey,
            BaseEncoding.base16().encode(domain),
            BaseEncoding.base16().encode(username),
            BaseEncoding.base16().encode(password)
        );
    }
}
