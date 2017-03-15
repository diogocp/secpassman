package io.github.diogocp.secpassman.server;

import com.google.common.collect.EvictingQueue;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Queues;
import com.google.common.collect.Table;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Queue;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class User implements Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(User.class);

    private static final Base64.Encoder base64 = Base64.getEncoder();

    private PublicKey publicKey;
    private Table<String, String, byte[]> passwords;

    private final Queue<UUID> authTokens;

    User(PublicKey publicKey) {
        this.publicKey = publicKey;
        passwords = HashBasedTable.create();
        authTokens = EvictingQueue.create(20);
        //Queues.synchronizedQueue(
    }

    byte[] getPassword(byte[] domain, byte[] username) {
        return passwords.get(base64.encodeToString(domain), base64.encodeToString(username));
    }

    void putPassword(byte[] domain, byte[] username, byte[] password) {
        passwords.put(base64.encodeToString(domain), base64.encodeToString(username), password);
    }

    UUID newAuthToken(UUID messageId) {
        UUID token = UUID.randomUUID();
        authTokens.add(token);
        return token;
    }

    boolean verifyAuthToken(UUID token) {
        if (token == null) {
            return false;
        }
        synchronized (authTokens) {
            if (authTokens.contains(token)) {
                authTokens.remove(token);
                return true;
            }
            return false;
        }
    }
}
