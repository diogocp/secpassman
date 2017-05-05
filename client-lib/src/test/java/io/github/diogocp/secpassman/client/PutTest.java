package io.github.diogocp.secpassman.client;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import io.github.diogocp.secpassman.common.messages.PutMessage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.Test;
import org.junit.Assert;

public class PutTest {


    private KeyPair keyPair;
    private PasswordManager manager;
    private Config config;
    private KeyStore keyStore;

    public PutTest() throws KeyStoreException, IOException {
        config = new Config("config.properties");
        keyStore = KeyStoreUtils.loadKeyStore("secpassman.jks", "jkspass");
        manager = new PasswordManager(config.getServerswithPKey());
        manager.init(keyStore, "client", "jkspass");
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

    @Test
    public void noAuthKeyTest() throws IOException{
        String domain = "tecnico.ulisboa.pt";
        String username = "client5";
        String password = "password";
        HttpClient httpClient = new HttpClient("localhost", 4567);

        PasswordRecord newRecord = new PasswordRecord(domain.getBytes(StandardCharsets.UTF_8),
                username.getBytes(StandardCharsets.UTF_8),
                password.getBytes(StandardCharsets.UTF_8));
        RsaSealedObject<PasswordRecord> sealedRecord;

        try {
            sealedRecord = new RsaSealedObject<>(newRecord, keyPair.getPublic());
        } catch (InvalidKeyException | IOException e) {
            throw new RuntimeException("Failed to encrypt password record", e);
        }

        final PutMessage message = new PutMessage(keyPair.getPublic(),
                manager.getHmac(domain.getBytes(StandardCharsets.UTF_8), "domain"),
                manager.getHmac(username.getBytes(StandardCharsets.UTF_8), "username"),
                SerializationUtils.serialize(sealedRecord));

        HttpResponse response;
        try {
            response = Unirest.post(String.format("http://%s:%d/secpassman", "localhost", 4567))
                    .body(SerializationUtils.serialize(message))
                    .asString();
        } catch (UnirestException e) {

        }
    }

}
