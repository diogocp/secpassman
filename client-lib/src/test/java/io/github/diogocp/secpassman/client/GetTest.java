package io.github.diogocp.secpassman.client;

import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import io.github.diogocp.secpassman.common.messages.GetMessage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import org.junit.Assert;
import org.junit.Test;

public class GetTest {
    private KeyPair keyPair;
    private PasswordManager manager;
    private Config config;
    private KeyStore keyStore;

    public GetTest() {

        config = new Config("config.properties");

        try {
            keyStore = KeyStoreUtils.loadKeyStore("../secpassman.jks", "jkspass");
            keyPair = KeyStoreUtils.loadKeyPair(keyStore, "client", "jkspass");
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
        manager = new PasswordManager(config.getHost(), config.getPort());
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
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        String wrong = "wrongpassword";

        byte[] passwordRetrieved = wrong.getBytes();
        try {
            passwordRetrieved = manager.retrieve_password(domain.getBytes(StandardCharsets.UTF_8),
                    username.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
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
