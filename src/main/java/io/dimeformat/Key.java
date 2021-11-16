//
//  Key.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeUnsupportedProfileException;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import jdk.jshell.execution.Util;
import org.json.JSONObject;

public class Key extends Item {

    /// PUBLIC ///

    public final static String TAG = "KEY";

    @Override
    public String getTag() {
        return Key.TAG;
    }

    public Profile getProfile() {
        return this._profile;
    }

    public UUID getIssuerId() {
        return this._claims.iss;
    }

    @Override
    public UUID getUniqueId() {
        return this._claims.uid;
    }

    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    public Instant getExpiresAt() {
        return this._claims.exp;
    }

    public KeyType getKeyType() {
        return this._type;
    }

    public byte[] getSecret() {
        return this._claims.key;
    }

    public byte[] getPublic() {
        return this._claims.pub;
    }

    public static Key generateKey(KeyType type) {
        try {
            return Key.generateKey(type, -1, Crypto.DEFAULT_PROFILE);
        } catch (DimeUnsupportedProfileException e) {
            throw new RuntimeException("This should not happen (K1001)");
        }
    }

    public static Key generateKey(KeyType type, long validFor, Profile profile) throws DimeUnsupportedProfileException {
        Key key = Crypto.generateKey(profile, type);
        if (validFor != -1) {
            key._claims.exp = key._claims.iat.plusSeconds(validFor);
        }
        return key;
    }

    public static Key fromBase58Key(byte[] base58key) {
        return null;
    }

    public Key publicCopy() {
        return new Key(this._claims.uid, this._type, null, this._claims.pub, this._profile);
    }

    /// PACKAGE-PRIVATE ///

    Key(UUID id, KeyType type, byte[] key, byte[] publicKey, Profile profile) {
        Instant iat = Instant.now();
        this._claims = new KeyClaims(null,
                                      id,
                                      iat,
                                     null,
                                     Key.encodeKey(key, (byte)type.value, (byte)KeyVariant.PRIVATE.value, (byte)profile.value),
                                     Key.encodeKey(publicKey, (byte)type.value, (byte)KeyVariant.PUBLIC.value, (byte)profile.value));
        this._type = type;
        this._profile = profile;
    }

    /// PROTECTED ///

    protected Key(String base58key) {
        //decodeKey(base58key);
    }

/*    protected static Key fromEncoded(String encoded) throws DimeFormatException {
        return null;
    }*/

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope._COMPONENT_DELIMITER);
        if (components.length != Key._NBR_EXPECTED_COMPONENTS) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected " + Key._NBR_EXPECTED_COMPONENTS + ", got " + components.length +"."); }
        if (components[Key._TAG_INDEX] != Key.TAG) { throw new DimeFormatException("Unexpected item tag, expected: " + Key.TAG + ", got " + components[Key._TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Key._CLAIMS_INDEX]);
        this._claims = new KeyClaims(json);

        this._encoded = encoded;
    }

    @Override
    protected String encode() {
        if (this._encoded == null) {
            StringBuffer buffer = new StringBuffer();
            buffer.append(Key.TAG);
            buffer.append(Envelope._COMPONENT_DELIMITER);
            buffer.append(Utility.toBase64(this._claims.toJSONString()));
        }
        return this._encoded;
    }

    /// PRIVATE ///

    private class KeyClaims {

        public UUID iss;
        public UUID uid;
        public Instant iat;
        public Instant exp;
        public byte[] key;
        public byte[] pub;

        public KeyClaims(UUID iss, UUID uid, Instant iat, Instant exp, byte[] key, byte[] pub) {
            this.iss = iss;
            this.uid = uid;
            this.iat = iat;
            this.exp = exp;
            this.key = key;
            this.pub = pub;
        }

        public KeyClaims(byte[] json) {
            JSONObject jsonObject = new JSONObject(json);
            this.iss = UUID.fromString(jsonObject.getString("iss"));
            this.uid = UUID.fromString(jsonObject.getString("uid"));
            this.iat = Instant.parse(jsonObject.getString("iat"));
            this.exp = Instant.parse(jsonObject.getString("exp"));
            this.key = Utility.fromBase64(jsonObject.getString("key"));
            this.pub = Utility.fromBase64(jsonObject.getString("pub"));
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            if (this.iss != null) { jsonObject.put("iss", this.iss.toString()); }
            jsonObject.put("uid", this.uid.toString());
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.exp != null) { jsonObject.put("exp", this.exp.toString()); }
            if (this.key != null) { jsonObject.put("key", "null"); }
            if (this.pub != null) { jsonObject.put("pub", "null"); }
            return jsonObject.toString();
        }

    }

    private static final int _NBR_EXPECTED_COMPONENTS = 2;
    private static final int _TAG_INDEX = 0;
    private static final int _CLAIMS_INDEX = 1;

    private KeyClaims _claims;
    private Profile _profile;
    private KeyType _type;

    private Key(byte[] json) {
        this._claims = new KeyClaims(json);
    }

    private static byte[] encodeKey(byte[] key, byte type, byte variant, byte profile) {
        if (key == null || key.length == 0) { return null; }
        byte combinedType = (byte) (type | variant); // TODO: verify this
        byte[] prefix = { 0x00, profile, combinedType, 0x00 };
        return null; // Base58.encode(Utility.combine(prefix, key));
    }

    private void decodeKey(byte[] encodedKey) throws DimeFormatException {
        if (encodedKey != null && encodedKey.length > 0) {
            byte[] bytes = Base58.decode(encodedKey);
            if (bytes.length > 0) {
                Profile profile = Profile.valueOf(bytes[1]);
                if (this._profile != Profile.UNDEFINED && profile != this._profile) { throw new DimeFormatException("Cryptographic profile version mismatch, got: " + profile + ", expected: " + this._profile + "."); }
                this._profile = profile;
                KeyType type = KeyType.valueOf(bytes[2] & 0xFE);
                if (this._type != KeyType.UNDEFINED && type != this._type) { throw new DimeFormatException("Key type mismatch, got: " + type + ", expected: " + this._type + "."); }
                this._type = type;
                KeyVariant variant = KeyVariant.valueOf(bytes[2] & 0x01);
                switch (variant) {
                    case PRIVATE:
                        this._claims.key = Utility.subArray(bytes, 4);
                        break;
                    case PUBLIC:
                        this._claims.pub = Utility.subArray(bytes, 4);
                        break;
                }
            }
        }
    }

}
