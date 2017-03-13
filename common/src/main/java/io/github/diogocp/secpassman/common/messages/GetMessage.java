package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;

public class GetMessage extends Message {

    public final byte[] domain;
    public final byte[] username;

    public GetMessage(PublicKey publicKey, byte[] domain, byte[] username) {
        super(publicKey);

        this.domain = domain;
        this.username = username;
    }
}
