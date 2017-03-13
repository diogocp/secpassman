package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;

public class PutMessage extends Message {

    private final byte[] domain;
    private final byte[] username;
    private final byte[] password;

    public PutMessage(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        super(publicKey);

        this.domain = domain;
        this.username = username;
        this.password = password;
    }
}
