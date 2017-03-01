package io.github.diogocp.secpassman.client;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.UUID;

class PasswordRecord implements Serializable {

    private static final long serialVersionUID = 666L;

    private final UUID uuid;
    private final ZonedDateTime date;

    private final String domain;
    private final String username;
    private final String password;

    PasswordRecord(String domain, String username, String password) {
        uuid = UUID.randomUUID();
        date = ZonedDateTime.now();

        this.domain = domain;
        this.username = username;
        this.password = password;
    }

    public String getDomain() {
        return domain;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }


}
