package io.github.diogocp.secpassman.server.exceptions;

public class BadRequestException extends Exception {

    public BadRequestException() {
        super();
    }

    public BadRequestException(String s) {
        super(s);
    }

    public BadRequestException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public BadRequestException(Throwable throwable) {
        super(throwable);
    }
}
