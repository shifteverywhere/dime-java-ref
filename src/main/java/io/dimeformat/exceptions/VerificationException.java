package io.dimeformat.exceptions;

import io.dimeformat.Item;

public class VerificationException extends Exception {

    public enum Reason {

        NO_SIGNATURE,
        NOT_TRUSTED,
        KEY_MISMATCH,
        ISSUER_MISMATCH,
        USE_AFTER,
        USE_BEFORE,
        DATE_MISMATCH,
        LINKED_ITEM_FAULT,
        INVALID_ITEM,
        NO_KEY_RING,
        INTERNAL_ERROR

    }

    public final Reason reason;
    public final Item item;

    public VerificationException(Reason reason, Item item, String message) {
        this(reason, item, message, null);
    }

    public VerificationException(Reason reason, Item item, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
        this.item = item;
    }

    @Override
    public String toString() {
        return "VerificationException{" +
                "reason=" + reason +
                ", item=" + item +
                "} " + super.toString();
    }

}
