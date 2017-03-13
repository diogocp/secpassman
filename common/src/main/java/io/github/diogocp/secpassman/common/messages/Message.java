package io.github.diogocp.secpassman.common.messages;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignedObject;
import java.time.ZonedDateTime;
import java.util.UUID;

public class Message implements Serializable {

    private final UUID uuid;
    private final ZonedDateTime date;
    private final PublicKey publicKey;

    protected Message(PublicKey publicKey) {
        uuid = UUID.randomUUID();
        date = ZonedDateTime.now();

        this.publicKey = publicKey;
    }

    public SignedObject sign(PrivateKey privateKey)
            throws InvalidKeyException, IOException, SignatureException {
        // Set up the signing engine used to sign the object
        final Signature signingEngine;
        try {
            signingEngine = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the SHA256withRSA signature algorithm.
            throw new RuntimeException(e);
        }

        return new SignedObject(this, privateKey, signingEngine);
    }

    private static Message verify(SignedObject signedMessage, PublicKey verificationKey)
            throws InvalidKeyException, SignatureException, IOException, ClassNotFoundException {
        // The signing engine used to verify the object
        Signature verificationEngine;
        try {
            verificationEngine = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the SHA256withRSA signature algorithm.
            throw new RuntimeException(e);
        }

        if (signedMessage.verify(verificationKey, verificationEngine)) {
            Object message = signedMessage.getObject();
            if (message instanceof Message) {
                return (Message) message;
            } else {
                throw new ClassNotFoundException("Invalid message");
            }
        } else {
            throw new SignatureException("Message signature verification failed");
        }
    }
}
