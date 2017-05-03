package io.github.diogocp.secpassman.client;

import io.github.diogocp.secpassman.common.KeyStoreUtils;
import io.github.diogocp.secpassman.common.messages.GetMessage;
import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.PutMessage;
import io.github.diogocp.secpassman.common.messages.RegisterMessage;
import io.github.diogocp.secpassman.common.messages.ServerReplyMessage;
import io.github.diogocp.secpassman.common.messages.TimestampReplyMessage;
import io.github.diogocp.secpassman.common.messages.TimestampRequestMessage;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignedObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordManager.class);

    private final Broadcaster broadcaster;

    private KeyPair keyPair;
    private final Signature sha256WithRsa;
    private final Mac hmacSha256;

    public PasswordManager(List<InetSocketAddress> serverList) {
        broadcaster = new Broadcaster(serverList);

        try {
            sha256WithRsa = Signature.getInstance("SHA256withRSA");
            hmacSha256 = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support these algorithms
            throw new RuntimeException(e);
        }
    }

    public void init(KeyStore keyStore, String keyAlias, String keyPassword) {
        try {
            this.keyPair = KeyStoreUtils.loadKeyPair(keyStore, keyAlias, keyPassword);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void register_user() throws InvalidKeyException, IOException {
        RegisterMessage message = new RegisterMessage(keyPair.getPublic());

        SignedObject signedMessage;
        try {
            signedMessage = message.sign(keyPair.getPrivate());
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        broadcaster.broadcastMessage(signedMessage);
    }

    public byte[] retrieve_password(byte[] domain, byte[] username)
            throws IOException, InvalidKeyException, SignatureException, ClassNotFoundException {
        final GetMessage message = new GetMessage(keyPair.getPublic(), getHmac(domain, "domain"),
                getHmac(username, "username"));

        // Get a timestamp for this message
        message.timestamp = getTimestamp(message.uuid);

        List<Message> responses = broadcaster.broadcastMessage(message.sign(keyPair.getPrivate()));

        long max_timestamp = 0;
        int max_timestamp_index = 0;
        for (int i = 0; i < responses.size(); i++) {
            try {
                Message responseMessage = Message
                        .deserializeSignedMessage(((ServerReplyMessage) responses.get(i)).response);
                if (keyPair.getPublic().equals(responseMessage.publicKey)) {
                    if (responseMessage.timestamp > max_timestamp) {
                        max_timestamp = responseMessage.timestamp;
                        max_timestamp_index = i;
                    }
                } else {
                    throw new SignatureException("Message not signed by us!");
                }
            } catch (IOException | ClassNotFoundException | SignatureException e) {
                LOG.warn("Message verification failed", e);
            }
        }

        byte[] msg = ((ServerReplyMessage) responses.get(max_timestamp_index)).msg;
        Message responseMessage = Message.deserializeSignedMessage(msg);
        broadcaster.broadcastMessage(SerializationUtils.deserialize(msg));

/*
        if (response == null) {
            throw new ClassNotFoundException("Server returned an empty response");
        }
*/
        if (!(responseMessage instanceof PutMessage)) {
            throw new ClassNotFoundException("Server returned an invalid response");
        }

        RsaSealedObject<PasswordRecord> rsaSealedObject;
        try {
            byte[] passwordRecord = ((PutMessage) responseMessage).password;
            rsaSealedObject = RsaSealedObject.safeDeserialize(passwordRecord);
        } catch (IOException e) {
            // TODO tried to deserialize wrong class?
            throw new RuntimeException(e);
        }

        try {
            PasswordRecord record = rsaSealedObject.getObject(keyPair.getPrivate());

            if (Arrays.equals(domain, record.getDomain())
                    && Arrays.equals(username, record.getUsername())) {
                return record.getPassword();
            } else {
                // TODO handle server replying with a legit record that is not the one we requested
                return null;
            }
        } catch (InvalidKeyException | IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            // TODO sig verification failed
            return null;
        }
    }

    public void save_password(byte[] domain, byte[] username, byte[] password)
            throws InvalidKeyException, IOException, SignatureException, ClassNotFoundException {

        PasswordRecord newRecord = new PasswordRecord(domain, username, password);
        RsaSealedObject<PasswordRecord> sealedRecord;

        try {
            sealedRecord = new RsaSealedObject<>(newRecord, keyPair.getPublic());
        } catch (InvalidKeyException | IOException e) {
            throw new RuntimeException("Failed to encrypt password record", e);
        }

        final PutMessage message = new PutMessage(keyPair.getPublic(), getHmac(domain, "domain"),
                getHmac(username, "username"), SerializationUtils.serialize(sealedRecord));

        // Get an auth token for this message, to prevent replay attacks
        message.timestamp = getTimestamp(message.uuid);

        broadcaster.broadcastMessage(message.sign(keyPair.getPrivate()));
    }

    public void close() {
    }

    public byte[] getHmac(byte[] message, String context) {
        final byte[] messageToSign;

        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            // We use a context label to provide domain separation
            final String ctxLabel = String.format("secpassman record for %s: ", context);
            bos.write(ctxLabel.getBytes(StandardCharsets.US_ASCII));
            bos.write(message);
            messageToSign = bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            // Sign the message
            sha256WithRsa.initSign(keyPair.getPrivate());
            sha256WithRsa.update(messageToSign);
            final byte[] signature = sha256WithRsa.sign();

            // Use the message signature as the HMAC key
            hmacSha256.init(new SecretKeySpec(signature, "HmacSHA256"));
        } catch (InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }

        return hmacSha256.doFinal(messageToSign);
    }

    public long getTimestamp(UUID messageId)
            throws InvalidKeyException, SignatureException, IOException, ClassNotFoundException {
        TimestampRequestMessage message = new TimestampRequestMessage(keyPair.getPublic(),
                messageId);

        List<Message> responses = broadcaster.broadcastMessage(message.sign(keyPair.getPrivate()));
        Message responseMessage = getMessageWithMaxTimestamp(responses);

        if ((responseMessage instanceof TimestampReplyMessage)
                && ((TimestampReplyMessage) responseMessage).messageId.equals(messageId)) {
            return ((TimestampReplyMessage) responseMessage).timestamp;
        }
        throw new ClassNotFoundException("Invalid timestamp response");
    }

    private Message getMessageWithMaxTimestamp(List<Message> responses) throws IOException {
        return responses.stream().max((m1, m2) -> {
            if (m1.timestamp > m2.timestamp) {
                return 1;
            } else if (m1.timestamp < m2.timestamp) {
                return -1;
            }
            return 0;
        }).orElse(null);
    }
}
