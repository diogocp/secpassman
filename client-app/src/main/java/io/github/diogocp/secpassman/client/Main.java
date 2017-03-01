package io.github.diogocp.secpassman.client;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        KeyStore keyStore;
        try {
            keyStore = KeyStoreUtils.loadKeyStore("ClientKeyStore.jks", "ClientKeyPassword123");
        } catch (KeyStoreException | IOException e) {
            LOG.error("Error while loading key store", e);
            return;
        }

        // Round-trip test
        PasswordManager manager = new PasswordManager(new HttpClient("localhost", 4567));
        manager.init(keyStore, "ClientKey", "ClientKeyPassword123");
        manager.save_password("fenix.tecnico.ulisboa.pt".getBytes(), "ist123456".getBytes(), "superSecret!123".getBytes());
        LOG.info("Got password {}", new String(manager.retrieve_password("fenix.tecnico.ulisboa.pt".getBytes(), "ist123456".getBytes())));
    }
}
