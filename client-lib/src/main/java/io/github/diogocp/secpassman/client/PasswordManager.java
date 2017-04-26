package io.github.diogocp.secpassman.client;

import io.github.diogocp.secpassman.common.KeyStoreUtils;
import io.github.diogocp.secpassman.common.messages.GetMessage;
import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.PutMessage;
import io.github.diogocp.secpassman.common.messages.RegisterMessage;
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
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordManager.class);

    private final List<HttpClient> servers;
    private final int num_servers;
    private final int max_failures;

    private KeyPair keyPair;
    private final Signature sha256WithRsa;
    private final Mac hmacSha256;

    public PasswordManager(List<InetSocketAddress> serverList) {
        servers = serverList.stream().map(HttpClient::new).collect(Collectors.toList());
        num_servers = servers.size();
        max_failures = (servers.size() - 1) / 3;

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

        broadcastMessage(signedMessage);
    }

    public byte[] retrieve_password(byte[] domain, byte[] username)
            throws IOException, InvalidKeyException, SignatureException, ClassNotFoundException {
        final GetMessage message = new GetMessage(keyPair.getPublic(), getHmac(domain, "domain"),
                getHmac(username, "username"));

        // Get a timestamp for this message
        message.timestamp = getTimestamp(message.uuid);

        byte[] response = broadcastMessage(message.sign(keyPair.getPrivate()));

        if (response == null) {
            throw new ClassNotFoundException("Server returned an empty response");
        }

        Message responseMessage = Message.deserializeSignedMessage(response);
        if (!keyPair.getPublic().equals(responseMessage.publicKey)) {
            throw new SignatureException("Server response is not signed by us");

        }
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

        broadcastMessage(message.sign(keyPair.getPrivate()));
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
        TimestampRequestMessage message = new TimestampRequestMessage(keyPair.getPublic(), messageId);

        byte[] response = broadcastMessage(message.sign(keyPair.getPrivate()));

        Message responseMessage = Message.deserializeSignedMessage(response);

        if ((responseMessage instanceof TimestampReplyMessage)
                && ((TimestampReplyMessage) responseMessage).messageId.equals(messageId)) {
            return ((TimestampReplyMessage) responseMessage).timestamp;
        }
        throw new ClassNotFoundException("Invalid timestamp response");
    }

    private byte[] broadcastMessage(SignedObject message) throws IOException {
        byte[][] response = new byte[num_servers][];
        int num_failures = 0;

        for (int s = 0; s < num_servers; s++) {
            try {
                response[s] = servers.get(s).sendSignedMessage(message);
            } catch (IOException e) {
                num_failures++;
                LOG.warn("Sending message failed", e);
            }
        }

        if (num_failures <= max_failures) {
            return response[0];
        } else {
            throw new IOException("Failed broadcast");
        }
    }
}
