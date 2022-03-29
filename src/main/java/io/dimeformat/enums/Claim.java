package io.dimeformat.enums;

/**
 * Default claim names.
 */
public enum Claim {

    /**
     * Ambit
     */
    AMB,
    /**
     * Audience
     */
    AUD,
    /**
     * Capability
     */
    CAP,
    /**
     * Context
     */
    CTX,
    /**
     * Expires at
     */
    EXP,
    /**
     * Issued at
     */
    IAT,
    /**
     * Issuer
     */
    ISS,
    /**
     * Key
     */
    KEY,
    /**
     * Key ID
     */
    KID,
    /**
     * Link
     */
    LNK,
    /**
     * Method
     */
    MTD,
    /**
     * Public key
     */
    PUB,
    /**
     * Principles
     */
    PRI,
    /**
     * Subject
     */
    SUB,
    /**
     * System
     */
    SYS,
    /**
     * Unique ID
     */
    UID;

    @Override
    public String toString() {
        return super.toString().toLowerCase();
    }

    /**
     * Returns a Capability that matches the provided name.
     * @param name The name to match.
     * @return The matching Capability.
     * @throws IllegalArgumentException If no match could be done.
     */
    public static Capability from(String name) throws IllegalArgumentException {
        return Capability.valueOf(name.trim().toUpperCase());
    }

}
