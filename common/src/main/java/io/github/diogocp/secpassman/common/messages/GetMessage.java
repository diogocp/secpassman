package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;

public class GetMessage extends Message {

    private final byte[] domain;
    private final byte[] username;

    public GetMessage(PublicKey publicKey, byte[] domain, byte[] username) {
        super(publicKey);

        this.domain = domain;
        this.username = username;
    }
}
