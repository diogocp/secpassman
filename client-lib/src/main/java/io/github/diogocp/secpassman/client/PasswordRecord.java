package io.github.diogocp.secpassman.client;

import java.io.Serializable;

class PasswordRecord implements Serializable {

    private static final long serialVersionUID = 4065732678911393755L;

    private final byte[] domain;
    private final byte[] username;
    private final byte[] password;

    PasswordRecord(byte[] domain, byte[] username, byte[] password) {
        this.domain = domain;
        this.username = username;
        this.password = password;
    }

    byte[] getDomain() {
        return domain;
    }

    byte[] getUsername() {
        return username;
    }

    byte[] getPassword() {
        return password;
    }
}
