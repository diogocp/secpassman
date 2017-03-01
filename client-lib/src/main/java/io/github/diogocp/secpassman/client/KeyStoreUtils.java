package io.github.diogocp.secpassman.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;

class KeyStoreUtils {
    private KeyStoreUtils() {
        throw new UnsupportedOperationException("This class cannot be instantiated");
    }

    static KeyStore loadKeyStore(String filename, String password)
            throws KeyStoreException, IOException {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (FileInputStream fis = new FileInputStream(filename)) {
            keyStore.load(fis, password.toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException(e);
        }

        return keyStore;
    }

    static KeyPair loadKeyPair(KeyStore keyStore, String keyAlias, String password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException {

        Key key = keyStore.getKey(keyAlias, password.toCharArray());

        if (key instanceof PrivateKey) {
            return new KeyPair(keyStore.getCertificate(keyAlias).getPublicKey(), (PrivateKey) key);
        } else {
            throw new InvalidKeyException();
        }
    }
}
