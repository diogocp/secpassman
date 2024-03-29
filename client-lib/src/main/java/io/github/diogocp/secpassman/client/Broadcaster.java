package io.github.diogocp.secpassman.client;

import static java.util.stream.Collectors.toList;

import io.github.diogocp.secpassman.common.messages.FailureMessage;
import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.NullMessage;
import io.github.diogocp.secpassman.common.messages.ServerReplyMessage;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignedObject;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Broadcaster {

    private static final Logger LOG = LoggerFactory.getLogger(Broadcaster.class);

    private final Map<HttpClient, PublicKey> servers;
    private final int num_servers;
    private final int max_failures;

    Broadcaster(Map<InetSocketAddress, PublicKey> serverList) {
        servers = serverList.entrySet().stream()
                .map(server -> new AbstractMap.SimpleEntry<>(
                        new HttpClient(server.getKey()),
                        server.getValue()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        num_servers = servers.size();
        max_failures = (servers.size() - 1) / 3;
    }

    /**
     * Broadcast a message to all servers
     *
     * @param message The message to broadcast
     * @return A list of N-f responses
     */
    List<Message> broadcastMessage(SignedObject message) throws IOException {
        final List<Message> responses = new ArrayList<>();
        final LinkedBlockingQueue<Message> responseQueue = new LinkedBlockingQueue<>();

        // Start a thread for each server to send the message
        final List<Thread> threads = servers.entrySet().stream()
                .map(server -> new Thread(() -> {
                    try {
                        byte[] response = server.getKey().sendSignedMessage(message);

                        if(response == null) {
                            throw new IOException("Null response");
                        }

                        Message serverReplyMessage = Message.deserializeSignedMessage(response);

                        if (!server.getValue().equals(serverReplyMessage.publicKey)) {
                            throw new SignatureException(
                                    "ServerReplyMessage not signed by the correct key");
                        }

                        if (serverReplyMessage instanceof ServerReplyMessage) {
                            byte[] innerResponse = ((ServerReplyMessage) serverReplyMessage).response;
                            if (innerResponse != null) {
                                responseQueue.add(serverReplyMessage);
                            } else {
                                responseQueue.add(new NullMessage());
                            }
                        } else {
                            throw new ClassNotFoundException("Not instance of ServerReplyMessage");
                        }
                    } catch (IOException | ClassNotFoundException | SignatureException e) {
                        LOG.debug("Sending message failed", e);
                        responseQueue.add(new FailureMessage());
                    }
                }))
                .peek(Thread::start)
                .collect(toList());

        // Wait for N-f responses
        LOG.debug("Waiting for responses");
        int failures = 0;
        for (int i = 0; i < num_servers - max_failures; i++) {
            final Message response;
            try {
                response = responseQueue.take();
            } catch (InterruptedException e) {
                throw new IOException("Broadcast thread interrupted", e);
            }

            if (response instanceof FailureMessage) {
                if (++failures > max_failures) {
                    throw new IOException("Broadcast failed, too many failures");
                }
            } else {
                responses.add(response);
            }
        }

        // Interrupt remaining threads
        LOG.debug("Interrupting remaining threads");
        threads.forEach(Thread::interrupt);

        return responses;
    }
}
