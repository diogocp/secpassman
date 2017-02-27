package io.github.diogocp.secpassman.server;

import com.google.common.io.BaseEncoding;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class Utils {

    static void generateRsaKey(String filename) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kpair = kpg.genKeyPair();

            byte[] keyBytes = kpair.getPublic().getEncoded();
            String keyHex = BaseEncoding.base16().encode(keyBytes);

            FileOutputStream fos = new FileOutputStream(filename);
            fos.write(keyHex.getBytes());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static PublicKey readRsaKeyFromFile(String filename) {
        try {
            byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
            keyBytes = Base64.getUrlDecoder().decode(keyBytes);
            return parsePublicKey(keyBytes);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    static PublicKey parsePublicKey(byte[] keyBytes) {
        try {
            X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
