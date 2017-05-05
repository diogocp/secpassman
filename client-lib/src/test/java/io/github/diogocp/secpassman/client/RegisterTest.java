package io.github.diogocp.secpassman.client;

import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.junit.Test;
import java.io.IOException;

public class RegisterTest {

    private PasswordManager manager;

    public RegisterTest() throws KeyStoreException, IOException {
        final Config config = new Config("config.properties");
        final KeyStore keyStore = KeyStoreUtils.loadKeyStore("secpassman.jks", "jkspass");
        manager = new PasswordManager(config.getServerswithPKey());
        manager.init(keyStore, "client", "jkspass");
    }

    @Test
    public void success() throws IOException, InvalidKeyException {
        manager.register_user();
    }
}
