package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;

public class PutMessage extends Message {

    public final byte[] domain;
    public final byte[] username;
    public final byte[] password;

    public PutMessage(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        super(publicKey);

        this.domain = domain;
        this.username = username;
        this.password = password;
    }
}
