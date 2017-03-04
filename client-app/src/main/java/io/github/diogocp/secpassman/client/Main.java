package io.github.diogocp.secpassman.client;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import io.github.diogocp.secpassman.client.cli.CommandAddGet;
import io.github.diogocp.secpassman.client.cli.CommandMain;
import io.github.diogocp.secpassman.client.cli.CommandRegister;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        // Parse the command line
        CommandMain cmdMain = new CommandMain();
        CommandAddGet cmdAddGet = new CommandAddGet();
        JCommander cli = new JCommander(cmdMain);

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
            keyStore = KeyStoreUtils.loadKeyStore(cmdMain.getKeyStore(), "jkspass");
        } catch (KeyStoreException | IOException e) {
            LOG.error("Error while loading key store", e);
            return;
        }

        // Client API initialization
        PasswordManager manager = new PasswordManager(new HttpClient("localhost", 4567));
        manager.init(keyStore, "client", "jkspass");

        // Execute the user's command
        if ("register".equals(cli.getParsedCommand())) {
            manager.register_user();
            return;
        }

        // If the command is not 'register', it must be 'add' or 'get',
        // so parse the domain and username
        final byte[] domain = cmdAddGet.getDomain().getBytes(StandardCharsets.UTF_8);
        final byte[] username = cmdAddGet.getUsername().getBytes(StandardCharsets.UTF_8);

        if ("add".equals(cli.getParsedCommand())) {
            char[] password = System.console().readPassword("Please enter the password: ");
            manager.save_password(domain, username,
                    new String(password).getBytes(StandardCharsets.UTF_8));
            return;
        }

        if ("get".equals(cli.getParsedCommand())) {
            try {
                byte[] password = manager.retrieve_password(domain, username);
                System.out.println(new String(password));
            } catch (Exception e) {
                LOG.error("Error getting password", e);
            }
        }
    }
}
