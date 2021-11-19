//
//  Key.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.AlgorithmFamily;
import io.dimeformat.enums.KeyType;
import io.dimeformat.enums.KeyVariant;
import io.dimeformat.exceptions.DimeFormatException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import org.json.JSONObject;

public class Key extends Item {

    /// PUBLIC ///

    public final static String TAG = "KEY";

    @Override
    public String getTag() {
        return Key.TAG;
    }

    public int getVersion() {
        byte[] key = (this._claims.key != null) ? this._claims.key : this._claims.pub;
        return (int)(key[0]);
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
        byte[] key = (this._claims.key != null) ? this._claims.key : this._claims.pub;
        switch (Key.getAlgorithmFamily(key)) {
            case AEAD: return KeyType.ENCRYPTION;
            case ECDH: return KeyType.EXCHANGE;
            case EDDSA: return KeyType.IDENTITY;
            case HASH: return KeyType.AUTHENTICATION;
            default: return KeyType.UNDEFINED;
        }
    }

    public String getSecret() {
        return (this._claims.key != null) ? Base58.encode(this._claims.key, null) : null;
    }

    public String getPublic() {
        return (this._claims.pub != null) ? Base58.encode(this._claims.pub, null) : null;
    }

    public static Key generateKey(KeyType type) {
        return Key.generateKey(type, -1);
    }

    public static Key generateKey(KeyType type, long validFor) {
        Key key = Crypto.generateKey(type);
        if (validFor != -1) {
            key._claims.exp = key._claims.iat.plusSeconds(validFor);
        }
        return key;
    }

    public static Key fromBase58Key(String base58key) throws DimeFormatException {
        return new Key(base58key);
    }

    public Key publicCopy() {
        return new Key(this._claims.uid, this.getKeyType(), null, getRawPublic());
    }

    /// PACKAGE-PRIVATE ///

    Key(UUID id, KeyType type, byte[] key, byte[] pub) {
        Instant iat = Instant.now();
        this._claims = new KeyClaims(null,
                id,
                iat,
                null,
                (key != null) ? Utility.combine(Key.headerFrom(type, KeyVariant.SECRET), key) : null,
                (pub != null) ? Utility.combine(Key.headerFrom(type, KeyVariant.PUBLIC), pub) : null);
    }

    /// PACKAGE-PRIVATE ///

    Key() { }

    byte[] getRawSecret() {
        return (this._claims.key != null ) ? Utility.subArray(this._claims.key, Key._HEADER_SIZE, this._claims.key.length - Key._HEADER_SIZE) : null;
    }

    byte[] getRawPublic() {
        return (this._claims.pub != null ) ? Utility.subArray(this._claims.pub, Key._HEADER_SIZE, this._claims.pub.length - Key._HEADER_SIZE) : null;
    }


    /// PROTECTED ///

    protected Key(String base58key) throws DimeFormatException {
        if (base58key != null && base58key.length() > 0) {
            byte[] bytes = Base58.decode(base58key);
            if (bytes != null && bytes.length > 0) {
                switch (Key.getKeyVariant(bytes)) {
                    case SECRET:
                        this._claims = new KeyClaims(null, null, null, null, bytes, null);
                        break;
                    case PUBLIC:
                        this._claims = new KeyClaims(null, null, null, null, null, bytes);
                        break;
                }
                if (this._claims != null) { return; }
            }
        }
        throw new DimeFormatException("Invalid key. (K1010)");
    }

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope._COMPONENT_DELIMITER);
        if (components.length != Key._NBR_EXPECTED_COMPONENTS) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected " + Key._NBR_EXPECTED_COMPONENTS + ", got " + components.length +"."); }
        if (components[Key._TAG_INDEX].compareTo(Key.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + Key.TAG + ", got " + components[Key._TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Key._CLAIMS_INDEX]);
        this._claims = new KeyClaims(new String(json, StandardCharsets.UTF_8));
        this._encoded = encoded;
    }

    @Override
    protected String encode() {
        if (this._encoded == null) {
            StringBuffer buffer = new StringBuffer();
            buffer.append(Key.TAG);
            buffer.append(Envelope._COMPONENT_DELIMITER);
            buffer.append(Utility.toBase64(this._claims.toJSONString()));
            this._encoded = buffer.toString();
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

        public KeyClaims(String json) {
            JSONObject jsonObject = new JSONObject(json);
            this.iss = jsonObject.has("iss") ? UUID.fromString(jsonObject.getString("iss")) : null;
            this.uid = jsonObject.has("uid") ? UUID.fromString(jsonObject.getString("uid")) : null;
            this.iat = jsonObject.has("iat") ? Instant.parse(jsonObject.getString("iat")) : null;
            this.exp = jsonObject.has("exp") ? Instant.parse(jsonObject.getString("exp")) : null;
            this.key = jsonObject.has("key") ? Base58.decode(jsonObject.getString("key")) : null;
            this.pub = jsonObject.has("pub") ? Base58.decode(jsonObject.getString("pub")) : null;
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            if (this.iss != null) { jsonObject.put("iss", this.iss.toString()); }
            jsonObject.put("uid", this.uid.toString());
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.exp != null) { jsonObject.put("exp", this.exp.toString()); }
            if (this.key != null) { jsonObject.put("key", Base58.encode(this.key, null)); }
            if (this.pub != null) { jsonObject.put("pub",  Base58.encode(this.pub, null)); }
            return jsonObject.toString();
        }

    }

    private static final byte[] HEADER_AEAD = new byte[]         { (byte)0x01, (byte)0x10, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, AEAD, XChaCha20-Poly1305, 256-bit, extension, extension
    private static final byte[] HEADER_ECDH_SECRET = new byte[]  { (byte)0x01, (byte)0x40, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, public, extension, extension
    private static final byte[] HEADER_ECDH = new byte[]         { (byte)0x01, (byte)0x40, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, private, extension, extension
    private static final byte[] HEADER_EDDSA_SECRET = new byte[] { (byte)0x01, (byte)0x80, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, public, extension, extension
    private static final byte[] HEADER_EDDSA = new byte[]        { (byte)0x01, (byte)0x80, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, private, extension, extension
    private static final byte[] HEADER_HASH = new byte[]         { (byte)0x01, (byte)0xE0, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, Secure Hashing, Blake2b, 256-bit, extension, extension

    private static final int _NBR_EXPECTED_COMPONENTS = 2;
    private static final int _TAG_INDEX = 0;
    private static final int _CLAIMS_INDEX = 1;
    private static final int _HEADER_SIZE = 6;

    private KeyClaims _claims;

    private static byte[] headerFrom(KeyType type, KeyVariant variant) {
        switch (type) {
            case IDENTITY: return (variant == KeyVariant.SECRET) ? Key.HEADER_EDDSA_SECRET : Key.HEADER_EDDSA;
            case EXCHANGE: return (variant == KeyVariant.SECRET) ? Key.HEADER_ECDH_SECRET : Key.HEADER_ECDH;
            case ENCRYPTION: return HEADER_AEAD;
            case AUTHENTICATION: return HEADER_HASH;
            default: return null;
        }
    }

    private static AlgorithmFamily getAlgorithmFamily(byte[] key) {
        return AlgorithmFamily.valueOf(key[1]);
    }

    private static KeyVariant getKeyVariant(byte[] key) {
        AlgorithmFamily family = Key.getAlgorithmFamily(key);
        if (family == AlgorithmFamily.ECDH || family == AlgorithmFamily.EDDSA) {
            return KeyVariant.valueOf(key[3]);
        }
        return KeyVariant.SECRET;
    }

}
