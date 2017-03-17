package io.github.diogocp.secpassman.client;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignedObject;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class HttpClient {

    private static final Logger LOG = LoggerFactory.getLogger(HttpClient.class);

    private final String serverUrl;

    HttpClient(String host, int port) {
        serverUrl = String.format("http://%s:%d/secpassman", host, port);
    }

    public byte[] sendSignedMessage(SignedObject message) throws IOException {
        HttpResponse response;
        try {
            response = Unirest.post(serverUrl)
                    .body(SerializationUtils.serialize(message))
                    .asString();
        } catch (UnirestException e) {
            throw new IOException(e);
        }

        LOG.debug("Server response status: {} {}", response.getStatus(), response.getStatusText());

        if (response.getStatus() == 200) {
            InputStream is = response.getRawBody();
            final byte[] body = new byte[is.available()];
            is.read(body);
            is.close();
            return body;
        } else {
            return null;
        }
    }
}
