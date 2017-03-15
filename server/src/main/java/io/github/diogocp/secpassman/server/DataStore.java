package io.github.diogocp.secpassman.server;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

class DataStore {

    private Map<PublicKey, User> users = new HashMap<>();
    private final String fileName;

    @SuppressWarnings("unchecked")
    DataStore(String fileName) {
        this.fileName = fileName;

        try (FileInputStream file = new FileInputStream(fileName);
                ObjectInputStream in = new ObjectInputStream(file)) {
            users = (Map) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Unable to load file");
        }
    }

    private void saveFile() {
        try (FileOutputStream file = new FileOutputStream(fileName);
                ObjectOutputStream out = new ObjectOutputStream(file)) {
            out.writeObject(users);
        } catch (IOException e) {
            throw new RuntimeException("An error occurred while trying to create the file.", e);
        }
    }

    boolean containsUser(PublicKey publicKey) {
        return users.containsKey(publicKey);
    }

    void registerUser(PublicKey publicKey) {
        users.put(publicKey, new User(publicKey));
        this.saveFile();
    }

    User getUser(PublicKey publicKey) {
        return users.get(publicKey);
    }

    void putPassword(PublicKey publicKey, byte[] domain, byte[] username, byte[] password) {
        users.get(publicKey).putPassword(domain, username, password);
        this.saveFile();
    }

    byte[] getPassword(PublicKey publicKey, byte[] domain, byte[] username) {
        return users.get(publicKey).getPassword(domain, username);
    }
}
