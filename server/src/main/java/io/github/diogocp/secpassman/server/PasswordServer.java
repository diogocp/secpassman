package io.github.diogocp.secpassman.server;

import java.io.*;
import java.security.Key;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

class PasswordServer {

    private Map<Key, PasswordStore> store = new HashMap<>();

    PasswordServer(){
        //Load the file
        try{
            FileInputStream file = new FileInputStream("data.ser");
            ObjectInputStream in = new ObjectInputStream(file);
            store = (Map) in.readObject();
            in.close();
            file.close();
        }
        catch(IOException | ClassNotFoundException e){
            System.err.println("Unable to load file");
    }
    }

    void register(PublicKey publicKey) {
        if (store.containsKey(publicKey)) {
            throw new IllegalArgumentException("Already registered");
        }

        store.put(publicKey, new PasswordStore(publicKey));
        this.saveFile();
    }

    byte[] get(Key publicKey, byte[] domain, byte[] username) {
        return store.get(publicKey).get(domain, username);
    }

    void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
        store.get(publicKey).put(domain, username, password);
        this.saveFile();
    }

    private void saveFile(){
        try{
            FileOutputStream file = new FileOutputStream("data.ser");
            ObjectOutputStream out = new ObjectOutputStream(file);
            out.writeObject(store);
            out.close();
            file.close();
        }
        catch (IOException e){
            throw new RuntimeException("An error occurred while trying to create the file.\n" + e.getMessage());
        }
    }
}
