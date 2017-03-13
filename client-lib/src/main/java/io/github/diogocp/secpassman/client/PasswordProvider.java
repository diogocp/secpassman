package io.github.diogocp.secpassman.client;

import java.io.IOException;
import java.security.KeyPair;
import java.security.SignedObject;

interface PasswordProvider {

    void sendSignedMessage(SignedObject message) throws IOException;

    byte[] getPassword(KeyPair keyPair, byte[] domain, byte[] username);
}
