package io.github.diogocp.secpassman.client;

import io.github.diogocp.secpassman.common.KeyStoreUtils;
import io.github.diogocp.secpassman.common.PasswordRecord;
import io.github.diogocp.secpassman.common.SignedSealedObject;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.SerializationUtils;

public class PasswordManager implements Closeable {

    private KeyPair keyPair;
    private final PasswordProvider provider;

    private final Signature sha256WithRsa;
    private final Mac hmacSha256;

    public PasswordManager(PasswordProvider provider) {
        this.provider = provider;

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

    public void register_user() {
        provider.register(keyPair);
    }

    public byte[] retrieve_password(byte[] domain, byte[] username) {
        byte[] serializedRecord = provider.getPassword(keyPair, getHmac(domain, "domain"),
                getHmac(username, "username"));

        if (serializedRecord == null) {
            throw new IllegalArgumentException("Password record not found");
        }

        SignedSealedObject<PasswordRecord> signedSealedRecord;
        try {
            signedSealedRecord = SignedSealedObject.safeDeserialize(serializedRecord);
        } catch (IOException e) {
            // TODO tried to deserialize wrong class?
            throw new RuntimeException(e);
        }

        try {
            PasswordRecord record = signedSealedRecord.getObject(keyPair);

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

    public void save_password(byte[] domain, byte[] username, byte[] password) {
        PasswordRecord newRecord = new PasswordRecord(domain, username, password);
        SignedSealedObject<PasswordRecord> sealedRecord;

        try {
            sealedRecord = new SignedSealedObject<>(newRecord, keyPair);
        } catch (InvalidKeyException | IOException e) {
            throw new RuntimeException("Failed to encrypt password record", e);
        }

        byte[] serializedRecord = SerializationUtils.serialize(sealedRecord);

        provider.putPassword(keyPair, getHmac(domain, "domain"), getHmac(username, "username"),
                serializedRecord);
    }

    public void close() {
        //TODO not sure if we need anything here
    }

    private byte[] getHmac(byte[] message, String context) {
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
}
