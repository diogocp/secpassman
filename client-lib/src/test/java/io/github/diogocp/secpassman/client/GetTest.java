package io.github.diogocp.secpassman.client;

import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SignatureException;
import org.junit.Assert;
import org.junit.Test;

public class GetTest {

    private PasswordManager manager;
    private Config config;
    private KeyStore keyStore;

    public GetTest() throws KeyStoreException, IOException, InvalidKeyException {
        config = new Config("config.properties");
        keyStore = KeyStoreUtils.loadKeyStore("secpassman.jks", "jkspass");
        manager = new PasswordManager(config.getServerswithPKey());
        manager.init(keyStore, "client", "jkspass");
        manager.register_user();
    }

    @Test
    public void success()
            throws IOException, InvalidKeyException, SignatureException, ClassNotFoundException {
        String domain = "tecnico.ulisboa.pt";
        String username = "client4";
        String password = "password123!";

        manager.save_password(domain.getBytes(StandardCharsets.UTF_8),
                username.getBytes(StandardCharsets.UTF_8),
                password.getBytes(StandardCharsets.UTF_8));

        byte[] passwordRetrieved =
                manager.retrieve_password(domain.getBytes(StandardCharsets.UTF_8),
                        username.getBytes(StandardCharsets.UTF_8));

        Assert.assertEquals(password, new String(passwordRetrieved, StandardCharsets.UTF_8));
    }
}
