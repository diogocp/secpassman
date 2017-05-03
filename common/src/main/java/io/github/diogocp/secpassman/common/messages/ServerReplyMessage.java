package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;

public class ServerReplyMessage extends Message {

    public final byte[] response;

    public ServerReplyMessage(PublicKey publicKey, byte[] response) {
        super(publicKey);

        this.response = response;
    }
}
