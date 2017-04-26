package io.github.diogocp.secpassman.common.messages;

import java.security.PublicKey;
import java.util.UUID;

public class TimestampReplyMessage extends Message {

    public final UUID messageId;

    public TimestampReplyMessage(PublicKey publicKey, UUID messageId, long timestamp) {
        super(publicKey);
        this.messageId = messageId;
        this.timestamp = timestamp;
    }
}
