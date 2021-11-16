//
//  KeyVariant.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

public enum KeyVariant {

    PRIVATE(0x00),
    PUBLIC(0x01);

    KeyVariant(int value) {
        this.value = value;
    }

    public final int value;

    public static KeyVariant valueOf(int value) {

        switch (value) {
            case 0x00: return KeyVariant.PRIVATE;
            case 0x01: return KeyVariant.PUBLIC;
            default: throw new IllegalStateException("Unexpected value: " + value);
        }
    }

}
