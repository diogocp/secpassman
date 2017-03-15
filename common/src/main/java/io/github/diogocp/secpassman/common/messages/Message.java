package io.github.diogocp.secpassman.common.messages;

import java.io.ByteArrayInputStream;
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
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

public class Message implements Serializable {

    public final UUID uuid;
    public final ZonedDateTime date;
    public final PublicKey publicKey;

    public UUID authToken;

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

    public static boolean verify(SignedObject signedMessage, PublicKey verificationKey)
            throws InvalidKeyException, SignatureException {
        // The signing engine used to verify the object
        Signature verificationEngine;
        try {
            verificationEngine = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the SHA256withRSA signature algorithm.
            throw new RuntimeException(e);
        }

        return signedMessage.verify(verificationKey, verificationEngine);
    }

    public static Message getObject(SignedObject signedMessage)
            throws ClassNotFoundException, IOException, SignatureException {
        final Object obj = signedMessage.getObject();

        if (!(obj instanceof Message)) {
            throw new ClassNotFoundException("Invalid message");
        }

        try {
            final Message message = (Message) obj;
            if (verify(signedMessage, message.publicKey)) {
                return message;
            } else {
                throw new SignatureException("Message signature verification failed");
            }
        } catch (InvalidKeyException e) {
            throw new SignatureException("Message signature verification failed", e);
        }
    }

    public static Message deserializeSignedMessage(byte[] message)
            throws IOException, ClassNotFoundException, SignatureException {
        final ByteArrayInputStream is = new ByteArrayInputStream(message);
        final ValidatingObjectInputStream vis = new ValidatingObjectInputStream(is);

        vis.accept(SignedObject.class);
        vis.accept("[B"); // byte primitive type

        final SignedObject signedObject = (SignedObject) vis.readObject();

        return Message.getObject(signedObject);
    }
}
