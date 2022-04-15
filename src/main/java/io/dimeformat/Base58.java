//
//  Base58.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Encodes and decodes byte arrays and strings to and from base 58. This is mainly used
 * to encode/decode keys. 
 */
public final class Base58 {

    /// PUBLIC ///

    /**
     * Encodes a byte array and an optional prefix to base 58. The prefix will be added to
     * the front of the data array.
     * @param data The main byte array to encode.
     * @param prefix A byte array that will be added to the front of data before encoding.
     * @return Base 58 encoded string
     */
    public static String encode(byte[] data, byte[] prefix) {
        if (data != null && data.length > 0) {
            int length = (prefix != null) ? prefix.length + data.length : data.length;
            byte[] bytes = new byte[length + Base58.NBR_CHECKSUM_BYTES];
            if (prefix != null) {
                System.arraycopy(prefix, 0, bytes, 0, prefix.length);
                System.arraycopy(data, 0, bytes, prefix.length, data.length);
            } else {
                System.arraycopy(data, 0, bytes, 0, length);
            }
            byte[] checksum = Base58.doubleHash(bytes, length);
            if (checksum.length > 0) {
                System.arraycopy(checksum, 0, bytes, length, Base58.NBR_CHECKSUM_BYTES);
                // Count leading zeros, to know where to start
                int start = 0;
                for (byte aByte : bytes) {
                    if (aByte != 0) {
                        break;
                    }
                    start++;
                }
                StringBuilder builder = new StringBuilder();
                bytes = Arrays.copyOf(bytes, bytes.length);
                for(int index = start; index < bytes.length;) {
                    builder.insert(0, _indexTable[calculateIndex(bytes, index, 256, 58)]);
                    if (bytes[index] == 0) {
                        ++index;
                    }
                }
                while (start > 0) {
                    builder.insert(0, '1');
                    start--;
                }
                return builder.toString();
            }
        }
        return null;
    }

    /**
     * Decodes a base 58 string to a byte array.
     * @param encoded The base 58 string that should be decoded.
     * @return A decoded byte array.
     */
    public static byte[] decode(String encoded) {
        if (encoded.length() == 0) {
            return new byte[0];
        }
        byte[] input58 = new byte[encoded.length()];
        for (int i = 0; i < encoded.length(); ++i) {
            char c = encoded.charAt(i);
            int digit = (c < 128) ? Base58._reverseTable[c] : -1;
            input58[i] = (byte) digit;
        }
        // Count leading zeros to know how many to restore
        int start = 0;
        while (start < input58.length && input58[start] == 0) {
            ++start;
        }
        byte[] decoded = new byte[encoded.length()];
        int position = decoded.length;
        for (int index = start; index < input58.length; ) {
            decoded[--position] = calculateIndex(input58, index, 58, 256);
            if (input58[index] == 0) {
                ++index;
            }
        }
        while (position < decoded.length && decoded[position] == 0) {
            ++position;
        }
        byte[] result = Arrays.copyOfRange(decoded, position - start, decoded.length);
        byte[] data = Arrays.copyOfRange(result, 0, result.length - Base58.NBR_CHECKSUM_BYTES);
        byte[] checksum = Arrays.copyOfRange(result, result.length - Base58.NBR_CHECKSUM_BYTES, result.length);
        byte[] actualChecksum = Arrays.copyOfRange(Base58.doubleHash(data, data.length), 0, Base58.NBR_CHECKSUM_BYTES);
        if (Arrays.equals(checksum, actualChecksum)) {
            return data;
        }
        return new byte[0];
    }

    /// PRIVATE //

    private static final int NBR_CHECKSUM_BYTES = 4;
    private static final char[] _indexTable = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] _reverseTable = new int[128];
    static {
        Arrays.fill(Base58._reverseTable, -1);
        for (int i = 0; i < Base58._indexTable.length; i++) {
            Base58._reverseTable[Base58._indexTable[i]] = i;
        }
    }

    private Base58() {
        throw new IllegalStateException("Not intended to be instantiated.");
    }

    private static byte calculateIndex(byte[] bytes, int position, int base, int divisor) {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;
        for (int i = position; i < bytes.length; i++) {
            int digit = bytes[i] & 255;
            int temp = remainder * base + digit;
            bytes[i] = (byte)(temp / divisor);
            remainder = temp % divisor;
        }
        return (byte)remainder;
    }

    private static byte[] doubleHash(byte[] message, int len) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(message, 0, len);
            return digest.digest(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            return new byte[0];
        }
    }

}