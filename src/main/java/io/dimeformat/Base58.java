//
//  Base58.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

public class Base58 {

    /// PUBLIC ///

    public static String encode(byte[] data) {
        return null;
    }

    public static byte[] decode(String encoded) {
        return null;
    }

    /// PRIVATE ///

    private final int CHECKSUM_SIZE = 4;
    private final String indexTable = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private static byte[] generateChecksum(byte[] data) {
        return null;
    }

    private static boolean verifyChecksum(byte[] bytes, byte[] checksum) {
        return false;
    }

}
