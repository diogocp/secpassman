package io.github.diogocp.secpassman.server;

import com.sun.net.httpserver.HttpServer;
import io.github.diogocp.secpassman.common.Config;
import java.io.IOException;
import java.net.InetSocketAddress;

public class Main {

    public static void main(String[] args) {
        final ServerApi serverApi = new ServerApi();

        final Config config = new Config();
        final String ip = config.getHost();
        final int port = Integer.parseInt(config.getPort());

        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(ip, port), 0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        server.createContext("/secpassman", new RequestHandler(serverApi));
        server.setExecutor(null);
        server.start();
    }
}
