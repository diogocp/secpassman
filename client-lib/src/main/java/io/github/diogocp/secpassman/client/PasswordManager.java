package io.github.diogocp.secpassman.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import org.apache.commons.lang3.SerializationUtils;

public class PasswordManager {

    private KeyPair keyPair;
    private final PasswordProvider provider;

    private final Signature SHA256withRSA;
    private final MessageDigest SHA256;

    PasswordManager(PasswordProvider provider) {
        this.provider = provider;

        try {
            SHA256withRSA = Signature.getInstance("SHA256withRSA");
            SHA256 = MessageDigest.getInstance("SHA-256");
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
        byte[] recordIdentifier = generateRecordIdentifier(domain, username);

        byte[] serializedRecord = provider.getPassword(keyPair, recordIdentifier, recordIdentifier);

        if (serializedRecord == null) {
            throw new IllegalArgumentException("Password record not found");
        }

        SignedSealedObject<PasswordRecord> signedSealedRecord =
                SerializationUtils.deserialize(serializedRecord);

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

        byte[] recordIdentifier = generateRecordIdentifier(domain, username);

        provider.putPassword(keyPair, recordIdentifier, recordIdentifier, serializedRecord);
    }

    public void close() {
        //TODO not sure if we need anything here
    }

    private byte[] generateRecordIdentifier(byte[] domain, byte[] username) {
        byte[] recordId;

        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            bos.write("secpassman record identifier".getBytes(StandardCharsets.US_ASCII));
            bos.write("\0domain: ".getBytes(StandardCharsets.US_ASCII));
            bos.write(domain);
            bos.write("\0username: ".getBytes(StandardCharsets.US_ASCII));
            bos.write(username);

            recordId = bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            SHA256withRSA.initSign(keyPair.getPrivate());
            SHA256withRSA.update(recordId);

            SHA256.update(recordId);
            SHA256.update(SHA256withRSA.sign());
        } catch (InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }

        return SHA256.digest();
    }
}
