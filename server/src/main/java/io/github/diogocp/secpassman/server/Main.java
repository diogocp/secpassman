package io.github.diogocp.secpassman.server;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;

public class Main {

    public static void main(String[] args) {
        final ServerApi serverApi = new ServerApi();

        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(4567), 0);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        server.createContext("/secpassman", new RequestHandler(serverApi));
        server.setExecutor(null);
        server.start();
    }
}
