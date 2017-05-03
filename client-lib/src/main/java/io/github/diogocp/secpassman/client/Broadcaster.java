package io.github.diogocp.secpassman.client;

import static java.util.stream.Collectors.toList;

import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.NullMessage;
import io.github.diogocp.secpassman.common.messages.ServerReplyMessage;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SignatureException;
import java.security.SignedObject;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Broadcaster {

    private static final Logger LOG = LoggerFactory.getLogger(Broadcaster.class);

    private final List<HttpClient> servers;
    private final int num_servers;
    private final int max_failures;

    Broadcaster(List<InetSocketAddress> serverList) {
        servers = serverList.stream().map(HttpClient::new).collect(toList());
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
        final List<Thread> threads = servers.stream()
                .map(server -> new Thread(() -> {
                    try {
                        byte[] response = server.sendSignedMessage(message);

                        Message serverReplyMessage = Message.deserializeSignedMessage(response);

                        // TODO verify publicKey
                        //serverReplyMessage.publicKey

                        if (serverReplyMessage instanceof ServerReplyMessage) {
                            byte[] innerResponse = ((ServerReplyMessage) serverReplyMessage).response;
                            if (innerResponse != null) {
                                responseQueue.add(Message.deserializeSignedMessage(innerResponse));
                            } else {
                                responseQueue.add(new NullMessage());
                            }
                        } else {
                            throw new ClassNotFoundException("Not instance of ServerReplyMessage");
                        }
                    } catch (IOException | ClassNotFoundException | SignatureException e) {
                        LOG.warn("Sending message failed", e);
                    }
                }))
                .peek(Thread::start)
                .collect(toList());

        // Wait for N-f responses
        LOG.debug("Waiting for responses");
        for (int i = 0; i < num_servers - max_failures; i++) {
            try {
                final Message response = responseQueue.take();
                if (response != null) {
                    responses.add(response);
                }
            } catch (InterruptedException e) {
                throw new IOException("Broadcast thread interrupted", e);
            }
        }

        // Interrupt remaining threads
        LOG.debug("Interrupting remaining threads");
        threads.forEach(Thread::interrupt);

        if (responses.size() >= num_servers - max_failures) {
            return responses;
        } else {
            throw new IOException("Broadcast failed");
        }
    }
}
