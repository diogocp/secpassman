package io.github.diogocp.secpassman.client;

import com.google.common.hash.Hashing;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SignatureException;
import org.apache.commons.lang3.SerializationUtils;

public class PasswordManager {

    private final KeyPair keyPair;
    private final PasswordProvider provider;

    PasswordManager(KeyPair keyPair, PasswordProvider provider) {
        this.keyPair = keyPair;
        this.provider = provider;

        provider.register(keyPair);
    }

    String getPassword(String domain, String username) {
        byte[] domainHash = Hashing.sha256().hashUnencodedChars(domain).asBytes();
        byte[] usernameHash = Hashing.sha256().hashUnencodedChars(username).asBytes();

        byte[] serializedRecord = provider.getPassword(keyPair, domainHash, usernameHash);

        if(serializedRecord == null) {
            throw new IllegalArgumentException("Password record not found");
        }

        SignedSealedObject<PasswordRecord> signedSealedRecord =
                SerializationUtils.deserialize(serializedRecord);

        try {
            PasswordRecord record = signedSealedRecord.getObject(keyPair);

            if (domain.equals(record.getDomain()) && username.equals(record.getUsername())) {
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

    void setPassword(String domain, String username, String password) {
        PasswordRecord newRecord = new PasswordRecord(domain, username, password);
        SignedSealedObject<PasswordRecord> sealedRecord;

        try {
            sealedRecord = new SignedSealedObject<>(newRecord, keyPair);
        } catch (InvalidKeyException | IOException e) {
            throw new RuntimeException("Failed to encrypt password record", e);
        }

        byte[] serializedRecord = SerializationUtils.serialize(sealedRecord);

        byte[] domainHash = Hashing.sha256().hashUnencodedChars(domain).asBytes();
        byte[] usernameHash = Hashing.sha256().hashUnencodedChars(username).asBytes();

        provider.putPassword(keyPair, domainHash, usernameHash, serializedRecord);
    }
}
