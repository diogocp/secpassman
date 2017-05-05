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

    public GetTest() throws KeyStoreException, IOException {
        config = new Config("config.properties");
        keyStore = KeyStoreUtils.loadKeyStore("../secpassman.jks", "jkspass");
        manager = new PasswordManager(config.getServerswithPKey());
        manager.init(keyStore, "client", "jkspass");
    }

    @Test
    public void success() {
        String domain = "tecnico.ulisboa.pt";
        String username = "client4";
        String password = "password";
        try {
            manager.save_password(domain.getBytes(StandardCharsets.UTF_8),
                    username.getBytes(StandardCharsets.UTF_8),
                    password.getBytes(StandardCharsets.UTF_8));
        } catch (InvalidKeyException | IOException | SignatureException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        String wrong = "wrongpassword";

        byte[] passwordRetrieved = wrong.getBytes();
        try {
            passwordRetrieved = manager.retrieve_password(domain.getBytes(StandardCharsets.UTF_8),
                    username.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | InvalidKeyException | SignatureException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        String password2 = new String(passwordRetrieved);
        Assert.assertEquals(password, password2);
    }

    @Test
    public void noAuthKeyTest() {
        //GetMessage message = new GetMessage(keyPair.getPublic(), getHmac(domain, "domain"),
          //      getHmac(username, "username"));
    }
}
