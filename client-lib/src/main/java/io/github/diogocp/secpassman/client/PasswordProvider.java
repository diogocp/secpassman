package io.github.diogocp.secpassman.client;

import java.security.KeyPair;

interface PasswordProvider {

    void register(KeyPair keyPair);

    byte[] getPassword(KeyPair keyPair, byte[] domain, byte[] username);

    void putPassword(KeyPair keyPair, byte[] domain, byte[] username, byte[] password);
}
