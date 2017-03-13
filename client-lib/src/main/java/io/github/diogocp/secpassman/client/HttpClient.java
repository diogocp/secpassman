package io.github.diogocp.secpassman.client;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.SignedObject;
import java.util.Base64;
import java.util.Base64.Encoder;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class HttpClient implements PasswordProvider {

    private static final Logger LOG = LoggerFactory.getLogger(HttpClient.class);
    private static final Encoder base64Url = Base64.getUrlEncoder().withoutPadding();

    private final URI serverUrl;

    HttpClient(String host, int port) {
        serverUrl = URI.create(String.format("http://%s:%d/", host, port));
    }

    public void sendSignedMessage(SignedObject message) throws IOException {
        HttpResponse response;
        try {
            response = Unirest.post(serverUrl.resolve("secpassman").toString())
                    .body(SerializationUtils.serialize(message))
                    .asString();
        } catch (UnirestException e) {
            throw new IOException(e);
        }

        LOG.info("sendSignedMessage status: {} {}", response.getStatus(), response.getStatusText());
    }

    public byte[] getPassword(KeyPair keyPair, byte[] domain, byte[] username) {
        byte[] clientKey = keyPair.getPublic().getEncoded();

        HttpResponse res;
        try {
            res = Unirest.get(serverUrl.resolve("password").toString())
                    .queryString("clientKey", base64Url.encodeToString(clientKey))
                    .queryString("domain", base64Url.encodeToString(domain))
                    .queryString("username", base64Url.encodeToString(username))
                    .asString();
        } catch (UnirestException e) {
            //TODO
            throw new RuntimeException(e);
        }

        LOG.info("Get password status: {} {}", res.getStatus(), res.getStatusText());
        if (res.getStatus() == 200) {
            try (InputStream is = res.getRawBody()) {
                final byte[] password = new byte[is.available()];
                is.read(password);
                return password;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            // TODO record not found
            return null;
        }
    }

    public void putPassword(KeyPair keyPair, byte[] domain, byte[] username, byte[] password) {
        byte[] clientKey = keyPair.getPublic().getEncoded();

        HttpResponse res;
        try {
            res = Unirest.put(serverUrl.resolve("password").toString())
                    .queryString("clientKey", base64Url.encodeToString(clientKey))
                    .queryString("domain", base64Url.encodeToString(domain))
                    .queryString("username", base64Url.encodeToString(username))
                    .body(password)
                    .asString();
        } catch (UnirestException e) {
            //TODO
            throw new RuntimeException(e);
        }

        LOG.info("Put password status: {} {}", res.getStatus(), res.getStatusText());
    }
}
