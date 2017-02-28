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

        HttpClient httpClient = new HttpClient("localhost", 4567, keyPair);
        httpClient.register();
        httpClient.register();

        // Round-trip test
        final byte[] testDomain = "http://test.com/".getBytes();
        final byte[] testUsername = "johnny_boy".getBytes();
        final byte[] testPassword = "superSecret123!".getBytes();
        httpClient.putPassword(testDomain, testUsername, testPassword);
        final byte[] response = httpClient.getPassword(testDomain, testUsername);
        LOG.info("\nI: {}\nO: {}", new String(testPassword), new String(response));
    }

}
