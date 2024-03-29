package io.github.diogocp.secpassman.client;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import io.github.diogocp.secpassman.client.cli.CommandAddGet;
import io.github.diogocp.secpassman.client.cli.CommandMain;
import io.github.diogocp.secpassman.client.cli.CommandRegister;
import io.github.diogocp.secpassman.common.Config;
import io.github.diogocp.secpassman.common.KeyStoreUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        // Parse the command line
        CommandMain cmdMain = new CommandMain();
        CommandAddGet cmdAddGet = new CommandAddGet();
        JCommander cli = new JCommander(cmdMain);
        Config config = new Config("config.properties");

        cli.addCommand("register", new CommandRegister());
        cli.addCommand("add", cmdAddGet);
        cli.addCommand("get", cmdAddGet);

        try {
            cli.parse(args);

            if (cmdMain.isHelp()) {
                cli.usage();
                return;
            }
            if (cli.getParsedCommand() == null) {
                throw new ParameterException("Please specify a command");
            }
            if (!"register".equals(cli.getParsedCommand())) {
                cmdAddGet.checkArgs();
            }
        } catch (ParameterException ex) {
            System.err.println(ex.getMessage());
            cli.usage();
            return;
        }

        // Load the key store
        KeyStore keyStore;
        try {
            if(!"secpassman.jks".equals(cmdMain.getKeyStore()))
            //ask for password
            {
                final char[] keystorePassword = System.console().readPassword("Keystore Password: ");
                cmdMain.setPassword(new String(keystorePassword));
            }

            keyStore = KeyStoreUtils.loadKeyStore(cmdMain.getKeyStore(), cmdMain.getKeystorePassword());
        } catch (KeyStoreException | IOException e) {
            LOG.error("Error while loading keystore", e);
            return;
        }

        try (PasswordManager manager = new PasswordManager(config.getServerswithPKey())) {
            // Client API initialization

            manager.init(keyStore, "client",cmdMain.getKeystorePassword());

            // Execute the user's command
            if ("register".equals(cli.getParsedCommand())) {
                manager.register_user();


            } else if ("add".equals(cli.getParsedCommand())) {
                final byte[] domain = cmdAddGet.getDomain().getBytes(StandardCharsets.UTF_8);
                final byte[] username = cmdAddGet.getUsername().getBytes(StandardCharsets.UTF_8);
                final char[] password = System.console().readPassword("Password: ");

                manager.save_password(domain, username,
                        new String(password).getBytes(StandardCharsets.UTF_8));

            } else if ("get".equals(cli.getParsedCommand())) {
                final byte[] domain = cmdAddGet.getDomain().getBytes(StandardCharsets.UTF_8);
                final byte[] username = cmdAddGet.getUsername().getBytes(StandardCharsets.UTF_8);

                try {
                    byte[] password = manager.retrieve_password(domain, username);
                    System.out.println(new String(password));
                } catch (Exception e) {
                    LOG.error("Error getting password", e);
                }
            }
        } catch (IOException | InvalidKeyException | SignatureException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
