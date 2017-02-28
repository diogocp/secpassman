package io.github.diogocp.secpassman.client;

import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;

import com.mashape.unirest.http.exceptions.UnirestException;
import java.net.URI;
import java.security.KeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpClient {

    private static final Logger LOG = LoggerFactory.getLogger(HttpClient.class);

    private final URI serverUrl;
    private final KeyPair keyPair;
    private final String clientKey;

    HttpClient(String host, int port, KeyPair keyPair) {
        serverUrl = URI.create(String.format("http://%s:%d/", host, port));

        this.keyPair = keyPair;
        clientKey = BaseEncoding.base16().encode(keyPair.getPublic().getEncoded());
    }

    void register() {
        HttpResponse res;
        try {
            res = Unirest.post(serverUrl.resolve("register").toString())
                    .queryString("clientKey", clientKey)
                    .asString();
        } catch (UnirestException e) {
            //TODO
            throw new RuntimeException(e);
        }

        LOG.info("Registration status: {} {}", res.getStatus(), res.getStatusText());
    }

    byte[] getPassword(byte[] domain, byte[] username) {
        HttpResponse res;
        try {
            res = Unirest.get(serverUrl.resolve("password").toString())
                    .queryString("clientKey", clientKey)
                    .queryString("domain", BaseEncoding.base16().encode(domain))
                    .queryString("username", BaseEncoding.base16().encode(username))
                    .asString();
        } catch (UnirestException e) {
            //TODO
            throw new RuntimeException(e);
        }

        LOG.info("Get password status: {} {}", res.getStatus(), res.getStatusText());
        return BaseEncoding.base16().decode(res.getBody().toString());
    }

    void putPassword(byte[] domain, byte[] username, byte[] password) {
        HttpResponse res;
        try {
            res = Unirest.put(serverUrl.resolve("password").toString())
                    .queryString("clientKey", clientKey)
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
