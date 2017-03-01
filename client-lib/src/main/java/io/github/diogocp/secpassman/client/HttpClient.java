package io.github.diogocp.secpassman.client;

import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import java.net.URI;
import java.security.KeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class HttpClient implements PasswordProvider {

    private static final Logger LOG = LoggerFactory.getLogger(HttpClient.class);

    private final URI serverUrl;

    HttpClient(String host, int port) {
        serverUrl = URI.create(String.format("http://%s:%d/", host, port));
    }

    public void register(KeyPair keyPair) {
        byte[] clientKey = keyPair.getPublic().getEncoded();

        HttpResponse res;
        try {
            res = Unirest.post(serverUrl.resolve("register").toString())
                    .queryString("clientKey", BaseEncoding.base16().encode(clientKey))
                    .asString();
        } catch (UnirestException e) {
            //TODO
            throw new RuntimeException(e);
        }

        LOG.info("Registration status: {} {}", res.getStatus(), res.getStatusText());
    }

    public byte[] getPassword(KeyPair keyPair, byte[] domain, byte[] username) {
        byte[] clientKey = keyPair.getPublic().getEncoded();

        HttpResponse res;
        try {
            res = Unirest.get(serverUrl.resolve("password").toString())
                    .queryString("clientKey", BaseEncoding.base16().encode(clientKey))
                    .queryString("domain", BaseEncoding.base16().encode(domain))
                    .queryString("username", BaseEncoding.base16().encode(username))
                    .asString();
        } catch (UnirestException e) {
            //TODO
            throw new RuntimeException(e);
        }

        LOG.info("Get password status: {} {}", res.getStatus(), res.getStatusText());
        if (res.getStatus() == 200) {
            return BaseEncoding.base16().decode(res.getBody().toString());
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
                    .queryString("clientKey", BaseEncoding.base16().encode(clientKey))
                    .queryString("domain", BaseEncoding.base16().encode(domain))
                    .queryString("username", BaseEncoding.base16().encode(username))
                    .queryString("password", BaseEncoding.base16().encode(password))
                    .asString();
        } catch (UnirestException e) {
            //TODO
            throw new RuntimeException(e);
        }

        LOG.info("Put password status: {} {}", res.getStatus(), res.getStatusText());
    }
}
