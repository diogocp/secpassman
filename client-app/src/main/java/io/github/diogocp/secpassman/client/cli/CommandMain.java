package io.github.diogocp.secpassman.client.cli;

import com.beust.jcommander.Parameter;

public class CommandMain {
    @Parameter(names = {"--help", "-h"}, help = true, hidden = true)
    private boolean help;

    @Parameter(names={"--keystore", "-k"}, description = "Path to the Java KeyStore (JKS) file")
    private String keyStore="secpassman.jks";

    @Parameter(names={"--password", "-p"}, description = "Java KeyStore (JKS) file password", hidden = true)
    private String keystorePassword="jkspass";

    public boolean isHelp() {
        return help;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public void setPassword(String password) { this.keystorePassword=password;}

    public String getKeystorePassword() { return keystorePassword;}
}
