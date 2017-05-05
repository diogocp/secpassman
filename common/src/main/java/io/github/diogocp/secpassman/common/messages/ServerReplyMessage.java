package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;
import java.util.UUID;

public class ServerReplyMessage extends Message {

    public final byte[] response;
    public final UUID reply_to;

    public ServerReplyMessage(PublicKey publicKey, byte[] response, UUID reply_to) {
        super(publicKey);

        this.response = response;
        this.reply_to = reply_to;
    }
}
