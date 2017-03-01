package io.github.diogocp.secpassman.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        final KeyPair keyPair;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            keyPair = kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // Round-trip test
        PasswordManager manager = new PasswordManager(keyPair, new HttpClient("localhost", 4567));
        manager.setPassword("fenix.tecnico.ulisboa.pt", "ist123456", "superSecret!123");
        LOG.info("Got password {}", manager.getPassword("fenix.tecnico.ulisboa.pt", "ist123456"));
    }
}
