package io.github.diogocp.secpassman.common;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.util.*;

public class Config {

    private final String host;
    private final String port;
    private final List<InetSocketAddress> servers = new ArrayList<>();

    public Config(String filename) {
        final Properties prop = new Properties();

        try (InputStream input = new FileInputStream(filename)) {
            prop.load(input);

            host = prop.getProperty("host", "");
            port = prop.getProperty("port", "");

            for (String server : prop.getProperty("servers", "").split(",")) {
                String[] ip_port = server.split(":");
                if (ip_port.length == 2) {
                    servers.add(new InetSocketAddress(ip_port[0], Integer.parseInt(ip_port[1])));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String getHost() {
        if (host.isEmpty()) {
            throw new RuntimeException("host not defined in properties");
        }
        return host;
    }

    public Integer getPort() {
        if (port.isEmpty()) {
            throw new RuntimeException("port not defined in properties");
        }
        return Integer.parseInt(port);
    }

    public List<InetSocketAddress> getServers() {
        return servers;
    }

    public Map<InetSocketAddress, PublicKey> getServerswithPKey() throws IOException {
        Map<InetSocketAddress, PublicKey> serverKeys = new HashMap<>();

        List<PublicKey> keys = KeyStoreUtils.loadCertificates("certs");
        for (int i = 0; i < getServers().size(); i++) {
            serverKeys.put(servers.get(i), keys.get(i));
        }

        return serverKeys;
    }
}
