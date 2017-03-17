package io.github.diogocp.secpassman.server;

import static org.apache.commons.lang3.ArrayUtils.EMPTY_BYTE_ARRAY;

import com.google.common.io.ByteStreams;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.github.diogocp.secpassman.common.messages.AuthReplyMessage;
import io.github.diogocp.secpassman.common.messages.AuthRequestMessage;
import io.github.diogocp.secpassman.common.messages.GetMessage;
import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.PutMessage;
import io.github.diogocp.secpassman.common.messages.RegisterMessage;
import io.github.diogocp.secpassman.server.exceptions.BadRequestException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.UUID;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

        // Register requests do not need an authentication token
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

        // Register requests also do not need an authentication token, but the user
        // must already be registered
        User user = dataStore.getUser(message.publicKey);
        if (user == null) {
            LOG.warn("Request denied: user not registered");
            sendResponse(httpExchange, 403, null);
            return;
        }
        LOG.debug("User is registered");

        if (message instanceof AuthRequestMessage) {
            LOG.debug("Handling authentication request");

            byte[] response = null;
            try {
                response = handleAuth((AuthRequestMessage) message);
            } catch (InvalidKeyException | SignatureException e) {
                LOG.error("Error while handling auth request", e);
            } finally {
                if (response == null) {
                    LOG.debug("Null auth reply");
                    sendResponse(httpExchange, 500, null);
                } else {
                    LOG.debug("Sending auth reply");
                    sendResponse(httpExchange, 200, response);
                }
            }
            return;
        }

        // All other requests need to provide a fresh authentication token
        LOG.debug("Message has auth token {}", message.authToken);

        if (!user.verifyAuthToken(message.authToken)) {
            LOG.warn("Request denied due to invalid authentication token");
            sendResponse(httpExchange, 403, null);
            return;
        }
        LOG.debug("Authentication token verified");

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

    private byte[] handleAuth(AuthRequestMessage message)
            throws InvalidKeyException, IOException, SignatureException {
        UUID authToken = dataStore.getUser(message.publicKey).newAuthToken(message.messageId);
        AuthReplyMessage response =
                new AuthReplyMessage(serverApi.keyPair.getPublic(), message.messageId, authToken);
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
        if (response == null) {
            httpExchange.sendResponseHeaders(status, 0);
            try (OutputStream os = httpExchange.getResponseBody()) {
                os.write(EMPTY_BYTE_ARRAY);
            }
        } else {
            httpExchange.sendResponseHeaders(status, response.length);
            try (OutputStream os = httpExchange.getResponseBody()) {
                os.write(response);
            }
        }
    }
}
