//
//  Crypto.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

public class Crypto {

    /// PUBLIC ///

    public static final Profile DEFAULT_PROFILE = Profile.UNO;

    public static boolean isSupportedProfile(Profile profile) {
        return profile == Crypto.DEFAULT_PROFILE;
    }

    public static String generateSignature(String data, Key key) {
        return null;
    }

    public static boolean verifySignature(String data, Key key) {
        return false;
    }

    public static Key generateKey(Profile profile, KeyType type) {
        return null;
    }

    public static Key generateSharedSecret(Key localKey, Key remoteKey, byte[] salt, byte[] info) {
        return null;
    }

    public static byte[] encrypt(byte[] plainText, Key key) {
        return null;
    }

    public static byte[] decrypt(byte[] cipherText, Key key) {
        return null;
    }

    public static byte[] generateHash(Profile profile, byte[] data) {
        return null;
    }

    /// PRIVATE ///


}
