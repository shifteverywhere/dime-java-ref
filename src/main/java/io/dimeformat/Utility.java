//
//  Utility.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/** Utility support methods. */
public final class Utility {

    /// PUBLIC ///

    /**
     * Generate secure random bytes.
     * @param length The number of bytes to generate.
     * @return
     */
    static byte[] randomBytes(final int length) {
        if (length <= 0) { return null; }
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Encode a byte array as a hexadecimal string.
     * @param bytes Byte array to encode.
     * @return Hexadecimal string.
     */
    static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_CHAR_SET[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHAR_SET[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Encode a byte array as a base 64 string.
     * @param bytes Byte array to encode.
     * @return Base 64 encoded string.
     */
    static String toBase64(byte[] bytes) {
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Encode a string as base 64.
     * @param string The string to encode.
     * @return Base 64 encoded string.
     */
    static String toBase64(String string) {
        return Utility.toBase64(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decode a base 64 encoded string.
     * @param base64 String to decode.
     * @return Decoded byte array.
     */
    static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Combine two byte arrays.
     * @param first First byte array.
     * @param second Second byte array.
     * @return First + second combined.
     */
    static byte[] combine(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    /**
     * Extract a sub-array from a byte array.
     * @param array The original byte array.
     * @param start The start position in of the sub-array in the original array.
     * @param length The length of the sub-array.
     * @return The extracted sub-array.
     */
    static byte[] subArray(byte[] array, int start, int length) {
        byte[] result = new byte[length];
        System.arraycopy(array, start, result, 0, length);
        return result;
    }

    /**
     * Extract a sub-array from a byte array.
     * @param array The original byte array.
     * @param start The start position in of the sub-array in the original array.
     * @return The extracted sub-array.
     */
    static byte[] subArray(byte[] array, int start) {
        return Utility.subArray(array, start, array.length - start);
    }

    /// PRIVATE ///

    private final static char[] HEX_CHAR_SET = "0123456789abcdef".toCharArray();

}
