package io.dimeformat.enums;

public enum Claim {

    AMB,
    AUD,
    CAP,
    CTX,
    EXP,
    IAT,
    ISS,
    KEY,
    KID,
    LNK,
    MTD,
    PUB,
    PRI,
    SUB,
    SYS,
    UID;

    @Override
    public String toString() {
        return super.toString().toLowerCase();
    }

    public static Capability from(String name) throws IllegalArgumentException {
        return Capability.valueOf(name.trim().toUpperCase());
    }

}
