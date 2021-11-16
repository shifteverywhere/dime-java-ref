package io.dimeformat.exceptions;

public class DimeFormatException extends Exception {

    public DimeFormatException(String message) {
        super(message);
    }

    public DimeFormatException(String message, Exception exception) {
        super(message, exception);
    }
}
