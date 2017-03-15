package io.github.diogocp.secpassman.server;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

class ServerApi {

    private Map<PublicKey, User> users = new HashMap<>();

    void register(PublicKey publicKey) {
        if (users.containsKey(publicKey)) {
            throw new IllegalArgumentException("Already registered");
        }

        users.put(publicKey, new User(publicKey));
        this.saveFile();
    }

    byte[] get(PublicKey publicKey, byte[] domain, byte[] username) {
        return users.get(publicKey).getPassword(domain, username);
    }

    void put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        users.get(publicKey).putPassword(domain, username, password);
        this.saveFile();
    }

    // Data persistence stuff
    @SuppressWarnings("unchecked")
    ServerApi() {
        //Load the file
        try (FileInputStream file = new FileInputStream("data.ser");
             ObjectInputStream in = new ObjectInputStream(file)) {
            users = (Map) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Unable to load file");
        }
    }

    private void saveFile() {
        try (FileOutputStream file = new FileOutputStream("data.ser");
             ObjectOutputStream out = new ObjectOutputStream(file)) {
            out.writeObject(users);
        } catch (IOException e) {
            throw new RuntimeException("An error occurred while trying to create the file.", e);
        }
    }
}
