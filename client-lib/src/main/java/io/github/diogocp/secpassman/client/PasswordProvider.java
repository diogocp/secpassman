package io.github.diogocp.secpassman.client;

import java.io.IOException;
import java.security.SignedObject;

interface PasswordProvider {

    byte[] sendSignedMessage(SignedObject message) throws IOException;
}
