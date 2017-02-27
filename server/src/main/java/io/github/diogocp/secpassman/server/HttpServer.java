package io.github.diogocp.secpassman.server;

import static spark.Spark.*;

import com.google.common.base.Throwables;
import com.google.common.io.BaseEncoding;
import java.security.PublicKey;

public class HttpServer {

    public static void main(String[] args) {
        final PasswordServer passwordServer = new PasswordServer();

        post("/register", (req, res) -> {

            byte[] keyBytes;

            try {
                keyBytes = BaseEncoding.base16().decode(req.queryParams("clientKey"));
            } catch (IllegalArgumentException | NullPointerException e) {
                res.status(400);
                return "Bad Request";
            }

            PublicKey clientKey = Utils.parsePublicKey(keyBytes);
            if (clientKey == null) {
                res.status(500);
                return "Error parsing clientKey.";
            }

            try {
                passwordServer.register(clientKey);
            } catch (IllegalArgumentException e) {
                res.status(409);
                return e.getMessage();
            }

            return "OK";
        });

        get("/password", (req, res) -> {

            byte[] keyBytes;
            byte[] domain;
            byte[] username;

            try {
                keyBytes = BaseEncoding.base16().decode(req.queryParams("clientKey"));
                domain = BaseEncoding.base16().decode(req.queryParams("domain"));
                username = BaseEncoding.base16().decode(req.queryParams("username"));
            } catch (IllegalArgumentException | NullPointerException e) {
                res.status(400);
                return "Bad Request";
            }

            PublicKey clientKey = Utils.parsePublicKey(keyBytes);
            try {
                byte[] password = passwordServer.get(clientKey, domain, username);
                if (password == null) {
                    return "null";
                }
                return BaseEncoding.base16().encode(password);
            } catch (Exception e) {
                res.status(500);
                return Throwables.getStackTraceAsString(e);
            }
        });

        put("/password", (req, res) -> {

            byte[] keyBytes;
            byte[] domain;
            byte[] username;
            byte[] password;

            try {
                keyBytes = BaseEncoding.base16().decode(req.queryParams("clientKey"));
                domain = BaseEncoding.base16().decode(req.queryParams("domain"));
                username = BaseEncoding.base16().decode(req.queryParams("username"));
                password = BaseEncoding.base16().decode(req.queryParams("password"));
            } catch (IllegalArgumentException | NullPointerException e) {
                res.status(400);
                return "Bad Request";
            }

            PublicKey clientKey = Utils.parsePublicKey(keyBytes);

            try {
                passwordServer.put(clientKey, domain, username, password);
                return "Stored password";
            } catch (Exception e) {
                res.status(500);
                return Throwables.getStackTraceAsString(e);
            }
        });
    }
}
