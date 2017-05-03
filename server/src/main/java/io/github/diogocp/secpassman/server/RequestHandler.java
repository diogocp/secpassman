package io.github.diogocp.secpassman.server;

import static org.apache.commons.lang3.ArrayUtils.EMPTY_BYTE_ARRAY;

import com.google.common.io.ByteStreams;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.github.diogocp.secpassman.common.messages.*;
import io.github.diogocp.secpassman.server.exceptions.BadRequestException;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SignedObject;

class RequestHandler implements HttpHandler {

    private static Logger LOG = LoggerFactory.getLogger(RequestHandler.class);

    private final ServerApi serverApi;
    private final DataStore dataStore;

    RequestHandler(ServerApi serverApi, DataStore dataStore) {
        super();
        this.serverApi = serverApi;
        this.dataStore = dataStore;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        LOG.info("Got a request from {}", httpExchange.getRemoteAddress());

        byte[] messageBytes;
        Message message;
        try {
            messageBytes = ByteStreams.toByteArray(httpExchange.getRequestBody());
            // Deserialization fails if the message is not signed with the private key
            // corresponding to the public key in the message.
            message = Message.deserializeSignedMessage(messageBytes);

        } catch (SignatureException | ClassNotFoundException e) {
            LOG.warn("Message deserialization failed", e);
            sendResponse(httpExchange, 400, null);
            return;
        }
        LOG.debug("Message signature verified");

        // Register requests do not need a timestamp
        if (message instanceof RegisterMessage) {
            LOG.debug("Handling register request");
            try {
                handleRegister((RegisterMessage) message);
                sendResponse(httpExchange, 200, null);
            } catch (BadRequestException e) {
                sendResponse(httpExchange, 400, null);
            }
            return;
        }

        // Register requests also do not need a timestamp, but the user
        // must already be registered
        User user = dataStore.getUser(message.publicKey);
        if (user == null) {
            LOG.warn("Request denied: user not registered");
            sendResponse(httpExchange, 403, null);
            return;
        }
        LOG.debug("User is registered");

        if (message instanceof TimestampRequestMessage) {
            LOG.debug("Handling timestamp request");

            byte[] response = null;
            try {
                response = handleTimestamp((TimestampRequestMessage) message);
            } catch (InvalidKeyException | SignatureException e) {
                LOG.error("Error while handling timestamp request", e);
            } finally {
                if (response == null) {
                    LOG.debug("Null timestamp reply");
                    sendResponse(httpExchange, 500, null);
                } else {
                    LOG.debug("Sending timestamp reply");
                    sendResponse(httpExchange, 200, response);
                }
            }
            return;
        }

        // All other requests need to provide a timestamp
        LOG.debug("Message has timestamp {}", message.timestamp);

        if (!user.verifyTimestamp(message.timestamp)) {
            LOG.warn("Ignored request with old timestamp");
            sendResponse(httpExchange, 200, null);
            return;
        }
        LOG.debug("Timestamp verified");

        if (message instanceof PutMessage) {
            LOG.debug("Handling put request");
            handlePut((PutMessage) message, messageBytes);
            sendResponse(httpExchange, 200, null);
        } else if (message instanceof GetMessage) {
            LOG.debug("Handling get request");
            byte[] password = handleGet((GetMessage) message);
            sendResponse(httpExchange, 200, password);
        } else {
            sendResponse(httpExchange, 400, null);
        }
    }

    private byte[] handleTimestamp(TimestampRequestMessage message)
            throws InvalidKeyException, IOException, SignatureException {
        long timestamp = dataStore.getUser(message.publicKey).getTimestamp();
        TimestampReplyMessage response =
                new TimestampReplyMessage(serverApi.keyPair.getPublic(), message.messageId,
                        timestamp);
        return SerializationUtils.serialize(response.sign(serverApi.keyPair.getPrivate()));
    }

    private void handleRegister(RegisterMessage message) throws BadRequestException {
        try {
            serverApi.register(message.publicKey);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e);
        }

    }

    private void handlePut(PutMessage message, byte[] rawMessage) {
        serverApi.put(message.publicKey, message.domain, message.username, rawMessage);
    }

    private byte[] handleGet(GetMessage message) {
        return serverApi.get(message.publicKey, message.domain, message.username);
    }

    private void sendResponse(HttpExchange httpExchange, int status, byte[] response)
            throws IOException {

        ServerReplyMessage res = new ServerReplyMessage(serverApi.keyPair.getPublic(), response);
        try {
            SignedObject signedMessage = res.sign(serverApi.keyPair.getPrivate());
            byte[] message = SerializationUtils.serialize(signedMessage);
            httpExchange.sendResponseHeaders(status, message.length);
            try (OutputStream os = httpExchange.getResponseBody()) {
                os.write(message);
            }
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }


    }
}
