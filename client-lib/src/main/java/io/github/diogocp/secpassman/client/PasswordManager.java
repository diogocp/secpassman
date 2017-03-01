package io.github.diogocp.secpassman.client;

import com.google.common.hash.Hashing;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SignatureException;
import java.util.Arrays;
import org.apache.commons.lang3.SerializationUtils;

public class PasswordManager {

    private KeyPair keyPair;
    private final PasswordProvider provider;

    PasswordManager(PasswordProvider provider) {
        this.provider = provider;
    }

    public void init(KeyStore keyStore, String keyAlias, String keyPassword) {
        try {
            this.keyPair = KeyStoreUtils.loadKeyPair(keyStore, keyAlias, keyPassword);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        provider.register(keyPair);
    }

    public void register_user() {
        provider.register(keyPair);
    }

    public byte[] retrieve_password(byte[] domain, byte[] username) {
        byte[] domainHash = Hashing.sha256().hashBytes(domain).asBytes();
        byte[] usernameHash = Hashing.sha256().hashBytes(domain).asBytes();

        byte[] serializedRecord = provider.getPassword(keyPair, domainHash, usernameHash);

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

        byte[] domainHash = Hashing.sha256().hashBytes(domain).asBytes();
        byte[] usernameHash = Hashing.sha256().hashBytes(domain).asBytes();

        provider.putPassword(keyPair, domainHash, usernameHash, serializedRecord);
    }

    public void close() {
        //TODO not sure if we need anything here
    }
}
