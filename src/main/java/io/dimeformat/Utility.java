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
import java.util.Date;

public final class Utility {

    private final static char[] hexCharacterSet = "0123456789abcdef".toCharArray();

    public static byte[] randomBytes(final int length) {
        if (length <= 0) { return null; }
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexCharacterSet[v >>> 4];
            hexChars[j * 2 + 1] = hexCharacterSet[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String toBase64(String string) {
        return Utility.toBase64(string.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    public static byte[] combine(byte[] first, byte[] second) {
        return null;
    }

    public static byte[] subArray(byte[] array, int start, int length) {
        return null;
    }

    public static byte[] subArray(byte[] array, int start) {
        return Utility.subArray(array, start, array.length - start);
    }

    public static byte[] prefix(byte prefix, byte[] array) {
        return null;
    }

    public static String toTimestamp(Date date) {
        return null;
    }

    public static Date fromTimestamp(String timestamp) {
        return null;
    }
}
