package io.github.diogocp.secpassman.client;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import io.github.diogocp.secpassman.common.messages.PutMessage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.Test;
import org.junit.Assert;

public class PutTest {


    private KeyPair keyPair;
    private PasswordManager manager;
    private Config config;
    private KeyStore keyStore;
    private Broadcaster broadcaster;

    public PutTest() throws KeyStoreException, IOException, InvalidKeyException, UnrecoverableKeyException, NoSuchAlgorithmException {
        config = new Config("config.properties");
        keyStore = KeyStoreUtils.loadKeyStore("secpassman.jks", "jkspass");
        manager = new PasswordManager(config.getServerswithPKey());
        manager.init(keyStore, "client", "jkspass");
        broadcaster = new Broadcaster(config.getServerswithPKey());
        keyPair = KeyStoreUtils.loadKeyPair(keyStore,"client","jkspass");
        manager.register_user();
    }

    @Test
    public void success() {
        String domain = "tecnico.ulisboa.pt";
        String username = "client4";
        String password = "password";
        try {
            manager.save_password( domain.getBytes(StandardCharsets.UTF_8),
                    username.getBytes(StandardCharsets.UTF_8),
                    password.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | InvalidKeyException | SignatureException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        String wrong = "wrongPassword";

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
}
