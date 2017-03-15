package io.github.diogocp.secpassman.server;

import com.google.common.io.ByteStreams;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.github.diogocp.secpassman.common.messages.GetMessage;
import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.PutMessage;
import io.github.diogocp.secpassman.common.messages.RegisterMessage;
import io.github.diogocp.secpassman.server.exceptions.BadRequestException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class RequestHandler implements HttpHandler {

    private static Logger LOG = LoggerFactory.getLogger(RequestHandler.class);

    private final ServerApi serverApi;

    RequestHandler(ServerApi serverApi) {
        super();
        this.serverApi = serverApi;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        Message message;
        try {
            // Deserialization fails if the message is not signed with the private key
            // corresponding to the public key in the message.
            message = Message.deserializeSignedMessage(
                    ByteStreams.toByteArray(httpExchange.getRequestBody()));

        } catch (SignatureException | ClassNotFoundException e) {
            LOG.warn("Message deserialization failed", e);
            sendResponse(httpExchange, 400, null);
            return;
        }
        LOG.debug("Message verification success");

        if (message instanceof RegisterMessage) {
            LOG.info("Handling register request");
            try {
                handleRegister((RegisterMessage) message);
                sendResponse(httpExchange, 200, null);
            } catch (BadRequestException e) {
                sendResponse(httpExchange, 400, null);
            }
        } else if (message instanceof PutMessage) {
            LOG.info("Handling put request");
            handlePut((PutMessage) message);
            sendResponse(httpExchange, 200, null);
        } else if (message instanceof GetMessage) {
            LOG.info("Handling get request");
            byte[] password = handleGet((GetMessage) message);
            sendResponse(httpExchange, 200, password);
        } else {
            sendResponse(httpExchange, 400, null);
        }
    }

    private void handleRegister(RegisterMessage message) throws BadRequestException {
        try {
            serverApi.register(message.publicKey);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e);
        }

    }

    private void handlePut(PutMessage message) {
        serverApi.put(message.publicKey, message.domain, message.username, message.password);
    }

    private byte[] handleGet(GetMessage message) {
        return serverApi.get(message.publicKey, message.domain, message.username);
    }

    private void sendResponse(HttpExchange httpExchange, int status, byte[] response)
            throws IOException {
        if (response == null) {
            httpExchange.sendResponseHeaders(status, 0);
            httpExchange.getResponseBody().close();
        } else {
            httpExchange.sendResponseHeaders(status, response.length);
            try (OutputStream os = httpExchange.getResponseBody()) {
                os.write(response);
            }
        }
    }
}
