package io.github.diogocp.secpassman.server;

import com.google.common.base.Throwables;
import io.github.diogocp.secpassman.common.messages.GetMessage;
import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.PutMessage;
import io.github.diogocp.secpassman.common.messages.RegisterMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Spark;

public class HttpServer {

    private static Logger LOG = LoggerFactory.getLogger(HttpServer.class);

    public static void main(String[] args) {
        final PasswordServer passwordServer = new PasswordServer();

        Spark.post("/secpassman", (req, res) -> {
            LOG.info("Got a request");

            Message message = Message.deserializeSignedMessage(req.bodyAsBytes());
            LOG.debug("Message verification success");

            if (message instanceof RegisterMessage) {
                LOG.info("Handling register request");

                try {
                    passwordServer.register(message.publicKey);
                    return "OK";
                } catch (IllegalArgumentException e) {
                    res.status(409);
                    return e.getMessage();
                }
            } else if (message instanceof PutMessage) {
                LOG.info("Handling put request");

                passwordServer.put(
                        ((PutMessage) message).publicKey,
                        ((PutMessage) message).domain,
                        ((PutMessage) message).username,
                        ((PutMessage) message).password);
                return "OK";
            } else if (message instanceof GetMessage) {
                LOG.info("Handling get request");

                try {
                    return passwordServer.get(
                            ((GetMessage) message).publicKey,
                            ((GetMessage) message).domain,
                            ((GetMessage) message).username);
                } catch (Exception e) {
                    res.status(500);
                    return Throwables.getStackTraceAsString(e);
                }
            } else {
                return "Not implemented";
            }
        });
    }
}
