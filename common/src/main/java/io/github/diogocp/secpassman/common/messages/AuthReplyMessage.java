package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;
import java.util.UUID;

public class AuthReplyMessage extends Message {

    public final UUID messageId;

    public AuthReplyMessage(PublicKey publicKey, UUID messageId, UUID authToken) {
        super(publicKey);
        this.messageId = messageId;
        this.authToken = authToken;
    }
}
