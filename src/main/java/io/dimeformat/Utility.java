//
//  Utility.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/** Utility support methods. */
public final class Utility {

    /// PUBLIC ///

    /**
     * Generate secure random bytes.
     * @param length The number of bytes to generate.
     * @return An array with secure random bytes.
     */
    public static byte[] randomBytes(final int length) {
        if (length <= 0) { return new byte[0]; }
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
    public static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_CHAR_SET[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHAR_SET[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] fromHex(String string) {
        int len = string.length();
        byte[] bytes = new byte[len >>> 1];
        for (int i = 0; i <= len - 2; i += 2) {
            bytes[i >>> 1] = (byte) (Integer.parseInt(string.substring(i, i + 2).trim(), 16) & 0xFF);
        }
        return bytes;
    }

    /**
     * Encode a byte array as a base 64 string.
     * @param bytes Byte array to encode.
     * @return Base 64 encoded string.
     */
    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Encode a string as base 64.
     * @param string The string to encode.
     * @return Base 64 encoded string.
     */
    public static String toBase64(String string) {
        return Utility.toBase64(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decode a base 64 encoded string.
     * @param base64 String to decode.
     * @return Decoded byte array.
     */
    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Combine two byte arrays.
     * @param first First byte array.
     * @param second Second byte array.
     * @return First + second combined.
     */
    public static byte[] combine(byte[] first, byte[] second) {
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
    public static byte[] subArray(byte[] array, int start, int length) {
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
    public static byte[] subArray(byte[] array, int start) {
        return Utility.subArray(array, start, array.length - start);
    }

    /**
     * Creates a timestamp that, if the global time modifier is set, will modify the timestamp accordingly. If no
     * modifier is set, then the current local time, in UTC, will be captured.
     * @return An Instant timestamp
     */
    public static Instant createTimestamp() {
        Instant now = Instant.now();
        long modifier = Dime.getTimeModifier();
        if (modifier == 0) { return now; }
        return now.plusSeconds(modifier);
    }

    /**
     * Will, if provided with a value different from 0 in gracePeriod, compare two Instant instances using a grace
     * period. A lower and upper boundary will be calculated from the base time given, the size of this period will be
     * based on value in gracePeriod. The value provided in gracePeriod should be in whole seconds. The result given
     * back will be equal to {@link Instant#compareTo(Instant)}. If 0 is provided as grace period, then the two Instant
     * instances will be compared normally.
     * @param baseTime The base time to compare a second Instant instance with.
     * @param otherTime The Instant instance to compare against the given base tne.
     * @param gracePeriod A period in seconds that should be allowed as grace when comparing.
     * @return Negative if less, positive is greater, or 0 if the same or within the grace period.
     */
    public static int gracefulTimestampCompare(Instant baseTime, Instant otherTime, long gracePeriod) {
        if (gracePeriod == 0) {
            return baseTime.compareTo(otherTime);
        } else {
            Instant lower = baseTime.minusSeconds(gracePeriod);
            int lowerResult = lower.compareTo(otherTime);
            Instant upper = baseTime.plusSeconds(gracePeriod);
            int upperResult = upper.compareTo(otherTime);
            if (lowerResult == upperResult) return lowerResult;
            return 0;
        }
    }

    /// PRIVATE ///

    private static final char[] HEX_CHAR_SET = "0123456789abcdef".toCharArray();

    private Utility() {
        throw new IllegalStateException("Not intended to be instantiated.");
    }

}
