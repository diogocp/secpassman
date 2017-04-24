package io.github.diogocp.secpassman.server;

import com.sun.net.httpserver.HttpServer;
import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

    private static Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        // Load the key pair
        final KeyPair keyPair;
        try {
            KeyStore keyStore = KeyStoreUtils.loadKeyStore("server.jks", "server");
            keyPair = KeyStoreUtils.loadKeyPair(keyStore, "server", "server");
        } catch (Exception e) {
            LOG.error("Error while loading key pair from keystore", e);
            return;
        }
        final DataStore dataStore = new DataStore("data.ser");
        final ServerApi serverApi = new ServerApi(keyPair, dataStore);

        final Config config = new Config("config.properties");
        final String ip = config.getHost();
        final int port = config.getPort();

        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(ip, port), 0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        server.createContext("/secpassman", new RequestHandler(serverApi, dataStore));
        server.setExecutor(null);
        LOG.info("Starting server");
        server.start();
    }
}
