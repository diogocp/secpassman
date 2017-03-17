package io.github.diogocp.secpassman.client;

import static org.junit.Assert.*;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import io.github.diogocp.secpassman.common.messages.GetMessage;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.http.NoHttpResponseException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.security.*;

public class RegisterTest {

    private static final Logger LOG = LoggerFactory.getLogger(RegisterTest.class);

    KeyPair keyPair;
    PasswordManager manager;
    Config config;
    KeyStore keyStore;

    public RegisterTest() {

        config = new Config();

        try {
            keyStore = KeyStoreUtils.loadKeyStore("../secpassman.jks", "jkspass");
            keyPair = KeyStoreUtils.loadKeyPair(keyStore, "client", "jkspass");
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }
        manager = new PasswordManager(config.getHost(), Integer.parseInt(config.getPort()));
        manager.init(keyStore, "client", "jkspass");
    }

    @Test
    public void success() {
        try {
            manager.register_user();
        } catch (IOException | InvalidKeyException e) {
            LOG.error("test failed", e);
            throw new RuntimeException(e);
        }
    }

    @Test
    public void RegisterWithRandomPrivateKeyTest() throws Exception {
        //signed incorrectly
        // not signed
        //  signed with other private key;
        //create message
        GetMessage message = new GetMessage(keyPair.getPublic(),
                manager.getHmac("domain".getBytes(), "domain"),
                manager.getHmac("username".getBytes(), "username"));

        // Get an auth token for this message, to prevent replay attacks
        message.authToken = manager.getAuthToken(message.uuid);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(2048, random);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        LOG.info("private key {}", priv);
        //PublicKey pub = pair.getPublic();

        // sign with diff key
        SignedObject signedMessage = message.sign(priv);

        //HttpClient httpClient = new HttpClient("localhost", 4567);
        // LOG.info("string > {}", config.getPort());

        HttpResponse response;
        try {
            response = Unirest.post(String.format("http://%s:%d/secpassman", "localhost", 4567))
                    .body(SerializationUtils.serialize(signedMessage))
                    .asString();
        } catch (UnirestException e) {
            throw new IOException(e);
        }

        assertTrue(response.getStatus() == 400);
    }

    @Test
    public void RegisterWithOthersPrivateKeyTest() throws Exception {
        KeyPair keyPairUser3 = KeyStoreUtils.loadKeyPair(keyStore, "client3", "jkspass");

        //create message
        GetMessage message = new GetMessage(keyPair.getPublic(),
                manager.getHmac("domain".getBytes(), "domain"),
                manager.getHmac("username".getBytes(), "username"));

        // Get an auth token for this message, to prevent replay attacks, not needed in register
        message.authToken = manager.getAuthToken(message.uuid);

        // sign with other user's private key
        SignedObject signedMessage = message.sign(keyPairUser3.getPrivate());

        HttpResponse response;
        try {
            response = Unirest.post(String.format("http://%s:%d/secpassman", "localhost", 4567))
                    .body(SerializationUtils.serialize(signedMessage))
                    .asString();
        } catch (UnirestException e) {
            throw new IOException(e);
        }

        assertTrue(response.getStatus() == 400);
    }

    @Test
    public void messageNotSignedTest() {
        //create message
        GetMessage message = new GetMessage(keyPair.getPublic(),
                manager.getHmac("domain".getBytes(), "domain"),
                manager.getHmac("username".getBytes(), "username"));

        HttpResponse response ;
        try {
            response = Unirest.post(String.format("http://%s:%d/secpassman", "localhost", 4567))
                    .body(SerializationUtils.serialize(message))
                    .asString();
        } catch (UnirestException e) {

        }
    }
}