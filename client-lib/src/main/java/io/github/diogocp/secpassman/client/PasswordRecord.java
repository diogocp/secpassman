package io.github.diogocp.secpassman.client;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.UUID;

public class PasswordRecord implements Serializable {

    private static final long serialVersionUID = 666L;

    private final UUID uuid;
    private final ZonedDateTime date;

    private final byte[] domain;
    private final byte[] username;
    private final byte[] password;

    public PasswordRecord(byte[] domain, byte[] username, byte[] password) {
        uuid = UUID.randomUUID();
        date = ZonedDateTime.now();

        this.domain = domain;
        this.username = username;
        this.password = password;
    }

    public byte[] getDomain() {
        return domain;
    }

    public byte[] getUsername() {
        return username;
    }

    public byte[] getPassword() {
        return password;
    }


}
