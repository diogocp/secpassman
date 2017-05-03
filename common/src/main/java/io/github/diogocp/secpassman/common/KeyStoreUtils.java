package io.github.diogocp.secpassman.common;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.io.File;
import java.util.HashMap;
import java.util.List;

public class KeyStoreUtils {
    private KeyStoreUtils() {
        throw new UnsupportedOperationException("This class cannot be instantiated");
    }

    public static KeyStore loadKeyStore(String filename, String password)
            throws KeyStoreException, IOException {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (FileInputStream fis = new FileInputStream(filename)) {
            keyStore.load(fis, password.toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException(e);
        }

        return keyStore;
    }

    public static KeyPair loadKeyPair(KeyStore keyStore, String keyAlias, String password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException {

        Key key = keyStore.getKey(keyAlias, password.toCharArray());

        if (key instanceof PrivateKey) {
            return new KeyPair(keyStore.getCertificate(keyAlias).getPublicKey(), (PrivateKey) key);
        } else {
            throw new InvalidKeyException();
        }
    }

    public static PublicKey loadPublicKeyFromCert(String filename) throws IOException{

        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream(filename);
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            PublicKey key = cer.getPublicKey();

            return key;
        }
        catch(FileNotFoundException | CertificateException e){
            throw new IOException(e);
        }
    }

    public static List<PublicKey> loadCertificates(String path) throws IOException {
        List<PublicKey> serverPubKeys = new ArrayList<>();

        File folder = new File(path);
        File[] listOfFiles = folder.listFiles();

        for (int i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile()) {
                PublicKey pkey = loadPublicKeyFromCert(path + "/" + listOfFiles[i].getName());
                serverPubKeys.add(pkey);
            }
        }
        return serverPubKeys;
    }
}
