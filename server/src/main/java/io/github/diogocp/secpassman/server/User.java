package io.github.diogocp.secpassman.server;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class User implements Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(User.class);

    private static final Base64.Encoder base64 = Base64.getEncoder();

    private PublicKey publicKey;
    private Table<String, String, byte[]> passwords;

    private AtomicLong timestamp;

    User(PublicKey publicKey) {
        this.publicKey = publicKey;
        passwords = HashBasedTable.create();
        timestamp = new AtomicLong(0);
    }

    byte[] getPassword(byte[] domain, byte[] username) {
        return passwords.get(base64.encodeToString(domain), base64.encodeToString(username));
    }

    void putPassword(byte[] domain, byte[] username, byte[] password) {
        passwords.put(base64.encodeToString(domain), base64.encodeToString(username), password);
    }

    long getTimestamp() {
        return timestamp.get();
    }

    boolean verifyTimestamp(long timestamp) {
        return this.timestamp.compareAndSet(timestamp, timestamp + 1);
    }
}
