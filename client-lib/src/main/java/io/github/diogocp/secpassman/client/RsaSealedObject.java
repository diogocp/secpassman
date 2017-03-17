package io.github.diogocp.secpassman.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

class RsaSealedObject<T extends Serializable> implements Serializable {

    private static final long serialVersionUID = 666L;

    private final SealedObject sealedObject;
    private final byte[] wrappedKey;

    RsaSealedObject(T object, PublicKey publicKey)
            throws InvalidKeyException, IOException {

        if (!publicKey.getAlgorithm().equals("RSA")) {
            throw new InvalidKeyException("Only RSA keys are supported.");
        }

        // Set up the key and cipher used to encrypt the object
        final SecretKey secretKey = generateSecretKey();
        final Cipher cipher = getCipher(secretKey);

        // Encrypt the object
        try {
            sealedObject = new SealedObject(object, cipher);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }

        // Wrap the key used to encrypt the object using the public key
        wrappedKey = wrapSecretKey(secretKey, publicKey);
    }

    T getObject(PrivateKey privateKey)
            throws InvalidKeyException, SignatureException, IOException, ClassNotFoundException {

        final SecretKey secretKey = unwrapSecretKey(wrappedKey, privateKey);

        try {
            return (T) sealedObject.getObject(secretKey);
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the AES/CBC/PKCS5Padding cipher.
            throw new RuntimeException(e);
        }
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

    static RsaSealedObject safeDeserialize(byte[] object) throws IOException {
        final ByteArrayInputStream is = new ByteArrayInputStream(object);
        final ValidatingObjectInputStream vis = new ValidatingObjectInputStream(is);

        vis.accept(RsaSealedObject.class, SealedObject.class);
        vis.accept("[B"); // byte primitive type

        try {
            return (RsaSealedObject) vis.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
