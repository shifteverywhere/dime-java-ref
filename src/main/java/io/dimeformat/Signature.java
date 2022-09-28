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

/**
 * Encapsulates a digital signature. A signature consists of two components, a key name and the actual signature. The
 * key name is used to identify the public key that may be used to verify the signature.
 */
public class Signature {

    /** The raw bytes of the signature. */
    final byte[] bytes;
    /** The key name for the key that may be used to verify the signature. */
    final String name;

    /**
     * Default constructor. If the name is omitted (null passed) then the signature will be considered as of legacy
     * format.
     * @param bytes The raw bytes of a signature.
     * @param name The key name.
     */
    Signature(byte[] bytes, String name) {
        this.bytes = bytes;
        this.name = name;
    }

    /**
     * Indicates if the signature is of legacy format.
     * @return True if legacy, false otherwise.
     */
    public boolean isLegacy() {
        return name == null;
    }

    /**
     * Decodes a string of encoded signatures and returns a list of Signature instances.
     * @param encoded The string of encoded signatures.
     * @return A list of Signature instances.
     */
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
                break; // No need to continue, legacy only supports one signature per item
            } else {
                try {
                    signatures.add(new Signature(Utility.fromHex(components[Signature.INDEX_SIGNATURE]), components[Signature.INDEX_KEY_NAME]));
                } catch (Exception e) {
                    // This is a legacy signature
                    signatures.add(new Signature(Utility.fromBase64(encoded), null));
                    break; // No need to continue, legacy only supports one signature per item
                }
            }
        }
        return signatures;
    }

    /**
     * Encodes a provided list of Signature instances to a string, used when exporting Dime items.
     * @param signatures A list of Signature instances to encode.
     * @return An encoded string.
     */
    static String toEncoded(List<Signature> signatures) {
        StringBuilder builder = new StringBuilder();
        boolean isLegacy = signatures.get(0).name == null;
        for(Signature signature: signatures) {
            if (builder.length() > 0) {
                builder.append(Dime.SECTION_DELIMITER);
            }
            signature.toEncoded(builder);
        }
        return isLegacy ? builder.toString() : Utility.toBase64(builder.toString());
    }

    /**
     * Finds a signature that matches a provided key name, if one is to be found.
     * @param name The key name to look for.
     * @param signatures A list of Signature instances to look in.
     * @return The found signature, or null if none could be found.
     */
    static Signature find(String name, List<Signature> signatures) {
        if (signatures == null) { return null; }
        return signatures.stream()
                .filter(signature -> name.equals(signature.name))
                .findAny()
                .orElse(null);
    }

    /// PRIVATE ///

    private static final int INDEX_KEY_NAME = 0;
    private static final int INDEX_SIGNATURE = 1;

    private void toEncoded(StringBuilder builder) {
        if (this.isLegacy()) {
            builder.append(Utility.toBase64(this.bytes));
        } else {
            builder.append(this.name);
            builder.append(Dime.COMPONENT_DELIMITER);
            builder.append(Utility.toHex(this.bytes));
        }
    }

}
