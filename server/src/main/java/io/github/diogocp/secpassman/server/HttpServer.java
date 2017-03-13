package io.github.diogocp.secpassman.server;

import static spark.Spark.*;

import com.google.common.base.Throwables;
import io.github.diogocp.secpassman.common.messages.Message;
import io.github.diogocp.secpassman.common.messages.RegisterMessage;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Request;

public class HttpServer {

    private static Logger LOG = LoggerFactory.getLogger(HttpServer.class);

    public static void main(String[] args) {
        final PasswordServer passwordServer = new PasswordServer();

        post("/secpassman", (req, res) -> {
            LOG.info("Got a request");

            Message message = Message.deserializeSignedMessage(req.bodyAsBytes());

            if (message instanceof RegisterMessage) {
                try {
                    passwordServer.register(message.publicKey);
                } catch (IllegalArgumentException e) {
                    res.status(409);
                    return e.getMessage();
                }
            }

            return "OK";
        });

        get("/password", (req, res) -> {
            final Map<String, byte[]> params = decodeQueryParams(req);
            final PublicKey clientKey = parsePublicKey(params.get("clientKey"));

            try {
                return passwordServer.get(clientKey, params.get("domain"), params.get("username"));
            } catch (Exception e) {
                res.status(500);
                return Throwables.getStackTraceAsString(e);
            }
        });

        put("/password", (req, res) -> {
            final Map<String, byte[]> params = decodeQueryParams(req);
            params.put("password", req.bodyAsBytes());
            final PublicKey clientKey = parsePublicKey(params.get("clientKey"));

            try {
                passwordServer.put(clientKey, params.get("domain"), params.get("username"),
                        params.get("password"));
                return "Stored password";
            } catch (Exception e) {
                res.status(500);
                return Throwables.getStackTraceAsString(e);
            }
        });
    }

    private static Map<String, byte[]> decodeQueryParams(Request req) {
        final Map<String, byte[]> params = new HashMap<>();
        for (Map.Entry<String, String[]> p : req.queryMap().toMap().entrySet()) {
            params.put(p.getKey(), Base64.getUrlDecoder().decode(p.getValue()[0]));
        }
        return params;
    }

    static PublicKey parsePublicKey(byte[] keyBytes) throws InvalidKeySpecException {
        try {
            final X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required to
            // support the RSA KeyFactory algorithm.
            throw new RuntimeException(e);
        }
    }
}
