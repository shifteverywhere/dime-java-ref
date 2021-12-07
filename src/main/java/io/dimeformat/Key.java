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

/**
 * Represents cryptographic keys. This may be keys for signing and verifying other Di:ME items and envelopes, used for
 * encryption purposes, or when exchanging shared keys between entities.
 */
public class Key extends Item {

    /// PUBLIC ///

    /** A tag identifying the Di:ME item type, part of the header. */
    public final static String TAG = "KEY";

    /**
     * Returns the tag of the Di:ME item.
     * @return The tag of the item.
     */
    @Override
    public String getTag() {
        return Key.TAG;
    }

    /**
     * Returns the version of the Di:ME specification for which this key was generated.
     * @return The Di:ME specification version of the key.
     */
    public int getVersion() {
        byte[] key = (this._claims.key != null) ? this._claims.key : this._claims.pub;
        return key[0];
    }

    /**
     * Returns the identifier of the entity that generated the key (issuer). This is optional.
     * @return The identifier of the issuer of the key.
     */
    public UUID getIssuerId() {
        return this._claims.iss;
    }

    /**
     * Returns a unique identifier for the instance. This will be generated at instance creation.
     * @return A unique identifier, as a UUID.
     */
    @Override
    public UUID getUniqueId() {
        return this._claims.uid;
    }

    /**
     * The date and time when this key was created.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    /**
     * Returns the expiration date of the key. This is optional.
     * @return
     */
    public Instant getExpiresAt() {
        return this._claims.exp;
    }

    /**
     * Returns the type of the key. The type determines what the key may be used for, this since it is also closely
     * associated with the cryptographic algorithm the key is generated for.
     * @return The type of the key.
     */
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

    /**
     * The secret part of the key. This part should never be stored or transmitted in plain text.
     * @return A base 58 encoded string.
     */
    public String getSecret() {
        return (this._claims.key != null) ? Base58.encode(this._claims.key, null) : null;
    }

    /**
     * The public part of the key. This part may be stored or transmitted in plain text.
     * @return A base 58 encoded string.
     */
    public String getPublic() {
        return (this._claims.pub != null) ? Base58.encode(this._claims.pub, null) : null;
    }

    /**
     * Will generate a new Key with a specified type.
     * @param type The type of key to generate.
     * @return A newly generated key.
     */
    public static Key generateKey(KeyType type) {
        return Key.generateKey(type, -1);
    }

    /**
     * Will generate a new Key with a specified type and an expiration date. Abiding to the expiration date is
     * application specific as the key will continue to function after the expiration date. Providing -1 as validFor
     * will skip setting an expiration date.
     * @param type The type of key to generate.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @return A newly generated key.
     */
    public static Key generateKey(KeyType type, long validFor) {
        Key key = Crypto.generateKey(type);
        if (validFor != -1) {
            key._claims.exp = key._claims.iat.plusSeconds(validFor);
        }
        return key;
    }

    /**
     * Will generate a new Key with a specified type, an expiration date, and the identifier of the issuer. Abiding to
     * the expiration date is application specific as the key will continue to function after the expiration date.
     * Providing -1 as validFor will skip setting an expiration date.
     * @param type The type of key to generate.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(KeyType type, long validFor, UUID issuerId) {
        Key key = Crypto.generateKey(type);
        if (validFor != -1) {
            key._claims.exp = key._claims.iat.plusSeconds(validFor);
        }
        key._claims.iss = issuerId;
        return key;
    }

    /**
     * Will instantiate a Key instance from a base 58 encoded string.
     * @param base58key A base 58 encoded key.
     * @return A Key instance.
     * @throws DimeFormatException If the format of the provided key string is invalid.
     */
    public static Key fromBase58Key(String base58key) throws DimeFormatException {
        return new Key(base58key);
    }

    /**
     * Will create a copy of a key with only the public part left. This should be used when transmitting a key to
     * another entity, when the receiving entity only needs the public part.
     * @return A new instance of the key with only the public part.
     */
    public Key publicCopy() {
        return new Key(this._claims.uid, this.getKeyType(), null, getRawPublic());
    }

    /// PACKAGE-PRIVATE ///

    Key() { }

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
            this._encoded = Key.TAG +
                    Envelope._COMPONENT_DELIMITER +
                    Utility.toBase64(this._claims.toJSONString());
        }
        return this._encoded;
    }

    /// PRIVATE ///

    private static final class KeyClaims {

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

    private static final int _NBR_EXPECTED_COMPONENTS = 2;
    private static final int _TAG_INDEX = 0;
    private static final int _CLAIMS_INDEX = 1;
    private static final int _HEADER_SIZE = 6;

    private KeyClaims _claims;

    private static byte[] headerFrom(KeyType type, KeyVariant variant) {
        AlgorithmFamily algorithmFamily = AlgorithmFamily.keyTypeOf(type);
        byte[] header = new byte[Key._HEADER_SIZE];
        header[0] = (byte)Envelope.DIME_VERSION;
        header[1] = algorithmFamily.value;
        switch (algorithmFamily) {
            case AEAD:
                header[2] = (byte) 0x01; // 0x01 == XChaCha20-Poly1305
                header[3] = (byte) 0x02; // 0x02 == 256-bit key size
                break;
            case ECDH:
                header[2] = (byte) 0x02; // 0x02 == X25519
                header[3] = variant.value;
                break;
            case EDDSA:
                header[2] = (byte) 0x01; // 0x01 == Ed25519
                header[3] = variant.value;
                break;
            case HASH:
                header[2] = (byte) 0x01; // 0x01 == Blake2b
                header[3] = (byte) 0x02; // 0x02 == 256-bit key size
                break;
        }
        return header;
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
