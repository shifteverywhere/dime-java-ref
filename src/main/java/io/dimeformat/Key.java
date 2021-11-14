//
//  Key.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.util.Date;
import java.util.UUID;

public class Key extends Item {

    /// PUBLIC ///

    public final static String TAG = "KEY";

    @Override
    public String getTag() {
        return Key.TAG;
    }

    public Profile getProfile() {
        return null;
    }

    public UUID getIssuerId() {
        return null;
    }

    @Override
    public UUID getUniqueId() {
        return null;
    }

    public Date getIssuedAt() {
        return null;
    }

    public KeyType getKeyType() {
        return null;
    }

    public String getSecret() {
        return null;
    }

    public String getPublic() {
        return null;
    }

    public static Key generateKey(KeyType type, double validFor, Profile profile) {
        return null;
    }

    public static Key fromBase58Key(String base58key) {
        return null;
    }

    public Key publicCopy() {
        return null;
    }

    /// PROTECTED ///

    protected Key(UUID id, KeyType type, byte[] key, byte[] publickey, Profile profile) {

    }

    protected Key(String base58key) {

    }

/*    protected static Key fromEncoded(String encoded) {
        return null;
    }*/

    @Override
    protected void decode(String encoded) {

    }

    @Override
    protected String encode() {
        return null;
    }
}
