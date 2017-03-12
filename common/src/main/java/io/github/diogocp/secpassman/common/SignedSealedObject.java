package io.github.diogocp.secpassman.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignedObject;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

public class SignedSealedObject<T extends Serializable> implements Serializable {

    private static final long serialVersionUID = 666L;

    private final SignedObject signedObject;

    public SignedSealedObject(T object, KeyPair keyPair)
            throws InvalidKeyException, IOException {

        if (!keyPair.getPublic().getAlgorithm().equals("RSA")) {
            throw new InvalidKeyException("Only RSA keys are supported.");
        }

        // Set up the key and cipher used to encrypt the object
        final SecretKey secretKey = generateSecretKey();
        final Cipher cipher = getCipher(secretKey);

        // Encrypt the object
        final SealedObject sealedObject;
        try {
            sealedObject = new SealedObject(object, cipher);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }

        // Wrap the key used to encrypt the object using the public key
        final byte[] wrappedKey = wrapSecretKey(secretKey, keyPair.getPublic());

        // Create a new object containing the sealed object and the key used to seal it (wrapped)
        final SealedObjectWrapper wrappedObject = new SealedObjectWrapper(sealedObject, wrappedKey);

        // Set up the signing engine used to sign the object
        final Signature signingEngine;
        try {
            signingEngine = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the SHA256withRSA signature algorithm.
            throw new RuntimeException(e);
        }

        try {
            signedObject = new SignedObject(wrappedObject, keyPair.getPrivate(), signingEngine);
        } catch (SignatureException e) {
            throw new InvalidKeyException(e);
        }
    }

    public T getObject(KeyPair keyPair)
            throws InvalidKeyException, SignatureException, IOException, ClassNotFoundException {

        if (!verify(keyPair.getPublic())) {
            throw new SignatureException("Signature verification failed.");
        }

        SealedObjectWrapper wrappedObject = (SealedObjectWrapper) signedObject.getObject();
        SecretKey secretKey = unwrapSecretKey(wrappedObject.getWrappedKey(), keyPair.getPrivate());

        try {
            return (T) wrappedObject.getObject(secretKey);
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the AES/CBC/PKCS5Padding cipher.
            throw new RuntimeException(e);
        }
    }

    private boolean verify(PublicKey verificationKey)
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

        return signedObject.verify(verificationKey, verificationEngine);
    }

    private static SecretKey generateSecretKey() {
        try {
            KeyGenerator generator;
            generator = KeyGenerator.getInstance("AES");
            generator.init(128);
            return generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the AES KeyGenerator algorithm.
            throw new RuntimeException(e);
        }
    }

    private static Cipher getCipher(SecretKey key) throws InvalidKeyException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Every implementation of the Java platform is required to
            // support the AES/CBC/PKCS5Padding cipher.
            throw new RuntimeException(e);
        }

    }

    private static byte[] wrapSecretKey(SecretKey secretKey, PublicKey publicKey)
            throws InvalidKeyException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            return cipher.wrap(secretKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Every implementation of the Java platform is required to
            // support the RSA/ECB/OAEPWithSHA-256AndMGF1Padding cipher.
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeyException("RSA key too small - must be at least 2048 bits", e);
        }
    }

    private static SecretKey unwrapSecretKey(byte[] wrappedKey, PrivateKey privateKey)
            throws InvalidKeyException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Every implementation of the Java platform is required to
            // support the RSA/ECB/OAEPWithSHA-256AndMGF1Padding cipher
            // and 128-bit AES keys.
            throw new RuntimeException(e);
        }
    }

    public static SignedSealedObject safeDeserialize(byte[] object)
            throws IOException {
        final ByteArrayInputStream is = new ByteArrayInputStream(object);
        final ValidatingObjectInputStream vis = new ValidatingObjectInputStream(is);

        vis.accept(SignedSealedObject.class, SignedObject.class);
        vis.accept("[B"); // byte primitive type

        try {
            return (SignedSealedObject) vis.readObject();
        } catch (ClassNotFoundException e) {
            // Impossible!
            throw new RuntimeException(e);
        }
    }

    private class SealedObjectWrapper extends SealedObject {

        private final byte[] wrappedKey;

        SealedObjectWrapper(SealedObject sealedObject, byte[] wrappedKey) {
            super(sealedObject);
            this.wrappedKey = wrappedKey;
        }

        byte[] getWrappedKey() {
            return wrappedKey;
        }
    }
}
