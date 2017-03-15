package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;
import java.util.UUID;

public class AuthRequestMessage extends Message{

    // This is the ID of the message we are going to send next, once we receive
    // an auth token. It's not the ID of this AuthRequestMessage itself!
    public final UUID messageId;

    public AuthRequestMessage(PublicKey publicKey, UUID messageId) {
        super(publicKey);
        this.messageId = messageId;
    }
}
