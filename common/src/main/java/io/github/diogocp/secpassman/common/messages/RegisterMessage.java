package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;

public class RegisterMessage extends Message {

    public RegisterMessage(PublicKey publicKey) {
        super(publicKey);
    }
}
