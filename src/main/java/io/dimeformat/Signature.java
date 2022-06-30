//
//  Signature.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

class Signature {

    final byte[] bytes;
    final String identifier;

    Signature(byte[] bytes, String identifier) {
        this.bytes = bytes;
        this.identifier = identifier;
    }

    public boolean isLegacy() {
        return identifier == null;
    }

    public static List<Signature> fromEncoded(String encoded) {
        if (encoded == null || encoded.isEmpty()) { throw new IllegalArgumentException("Encoded list of signatures must not be null or empty."); }
        ArrayList<Signature> signatures = new ArrayList<>();
        String decoded = new String(Utility.fromBase64(encoded), StandardCharsets.UTF_8);
        String[] items = decoded.split("\\" + Dime.SECTION_DELIMITER);
        for (String combined: items) {
            String[] components = combined.split("\\" + Dime.COMPONENT_DELIMITER);
            if (components.length == 1) {
                // This is a legacy signature
                signatures.add(new Signature(Utility.fromBase64(encoded), null));
            } else {
                try {
                    signatures.add(new Signature(Utility.fromHex(components[Signature.INDEX_SIGNATURE]), components[Signature.INDEX_KEY_IDENTIFIER]));
                } catch (Exception e) {
                    // This is a legacy signature
                    signatures.add(new Signature(Utility.fromBase64(encoded), null));
                }
            }
        }
        return signatures;
    }

    static String toEncoded(List<Signature> signatures) {
        StringBuilder builder = new StringBuilder();
        boolean isLegacy = signatures.get(0).identifier == null;
        for(Signature signature: signatures) {
            if (builder.length() > 0) {
                builder.append(Dime.SECTION_DELIMITER);
            }
            signature.toEncoded(builder);
        }
        return isLegacy ? builder.toString() : Utility.toBase64(builder.toString());
    }

    static Signature find(String identifier, List<Signature> signatures) {
        if (signatures == null) { return null; }
        return signatures.stream()
                .filter(signature -> identifier.equals(signature.identifier))
                .findAny()
                .orElse(null);
    }

    private void toEncoded(StringBuilder builder) {
        if (this.isLegacy()) {
            builder.append(Utility.toBase64(this.bytes));
        } else {
            builder.append(this.identifier);
            builder.append(Dime.COMPONENT_DELIMITER);
            builder.append(Utility.toHex(this.bytes));
        }
    }

    private static final int INDEX_KEY_IDENTIFIER = 0;
    private static final int INDEX_SIGNATURE = 1;

}
