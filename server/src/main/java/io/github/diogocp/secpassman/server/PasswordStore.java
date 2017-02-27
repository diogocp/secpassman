package io.github.diogocp.secpassman.server;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import java.security.Key;

class PasswordStore {

    private Key owner;
    private long version;
    private Table<String, String, String> store;

    PasswordStore(Key publicKey) {
        owner = publicKey;
        version = 1;
        store = HashBasedTable.create();
    }

    String get(String domain, String username) {
        return store.get(domain, username);
    }

    void put(String domain, String username, String password) {
        store.put(domain, username, password);
        version++;
    }
}
