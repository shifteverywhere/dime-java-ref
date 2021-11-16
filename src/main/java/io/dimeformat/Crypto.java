//
//  Crypto.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeIntegrityException;
import io.dimeformat.exceptions.DimeUnsupportedProfileException;
import io.dimeformat.libsodium.Sodium;
import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.*;
//import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import com.goterl.lazysodium.utils.LibraryLoader;
import com.sun.jna.NativeLong;

import java.util.UUID;

import static io.dimeformat.KeyType.*;

public class Crypto {

    /// PUBLIC ///

    public static final Profile DEFAULT_PROFILE = Profile.UNO;

    public static boolean isSupportedProfile(Profile profile) {
        return profile == Crypto.DEFAULT_PROFILE;
    }

    public static String generateSignature(String data, Key key) {
        return null;
    }

    public static boolean verifySignature(String data, String signature, Key key) throws DimeIntegrityException {
       throw new DimeIntegrityException("");
    }

    public static io.dimeformat.Key generateKey(Profile profile, KeyType type) throws DimeUnsupportedProfileException {
        if (!Crypto.isSupportedProfile(profile)) { throw new DimeUnsupportedProfileException(); }
        byte[] publicKey = new byte[32];
        byte[] secretKey = new byte[32];
        switch (type) {
            case IDENTITY:
                sodium.crypto_sign_keypair(publicKey, secretKey);
                break;
            case EXCHANGE:
                sodium.crypto_kx_keypair(publicKey, secretKey);
                break;
            default:
                throw new IllegalArgumentException("Unknown or unsupported key type.");
        }
        return new io.dimeformat.Key(UUID.randomUUID(), type, secretKey, publicKey, profile);
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

    private static final SodiumJava sodium = new SodiumJava();

}
