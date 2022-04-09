//
//  Key.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.AlgorithmFamily;
import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyType;
import io.dimeformat.enums.KeyVariant;
import io.dimeformat.exceptions.DimeFormatException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

/**
 * Represents cryptographic keys. This may be keys for signing and verifying other Di:ME items and envelopes, used for
 * encryption purposes, or when exchanging shared keys between entities.
 */
public class Key extends Item {

    /// PUBLIC ///

    /** A tag identifying the Di:ME item type, part of the header. */
    public static final String TAG = "KEY";

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
        byte[] key = claims.getBytes(Claim.KEY);
        if (key == null) { key = claims.getBytes(Claim.PUB); }
        return key[0];
    }

    /**
     * Returns the identifier of the entity that generated the key (issuer). This is optional.
     * @return The identifier of the issuer of the key.
     */
    public UUID getIssuerId() {
        return claims.getUUID(Claim.ISS);
    }

    /**
     * Returns a unique identifier for the instance. This will be generated at instance creation.
     * @return A unique identifier, as a UUID.
     */
    @Override
    public UUID getUniqueId() {
        return claims.getUUID(Claim.UID);
    }

    /**
     * The date and time when this key was created.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return claims.getInstant(Claim.IAT);
    }

    /**
     * Returns the expiration date of the key. This is optional.
     * @return The expiration date of the key.
     */
    public Instant getExpiresAt() {
        return claims.getInstant(Claim.EXP);
    }

    /**
     * Returns the type of the key. The type determines what the key may be used for, this since it is also closely
     * associated with the cryptographic algorithm the key is generated for.
     * @return The type of the key.
     */
    public KeyType getKeyType() {
        byte[] key = claims.getBytes(Claim.KEY);
        if (key == null) { key = claims.getBytes(Claim.PUB); }
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
        return claims.get(Claim.KEY);
    }

    /**
     * The public part of the key. This part may be stored or transmitted in plain text.
     * @return A base 58 encoded string.
     */
    public String getPublic() {
        return claims.get(Claim.PUB);
    }

    /**
     * Returns the context that is attached to the key.
     * @return A String instance.
     */
    public String getContext() {
        return claims.get(Claim.CTX);
    }

    /**
     * Will generate a new Key with a specified type.
     * @param type The type of key to generate.
     * @return A newly generated key.
     */
    public static Key generateKey(KeyType type) {
        return Key.generateKey(type, -1, null, null);
    }

    /**
     * Will generate a new Key with a specified type.
     * @param type The type of key to generate.
     * @param context The context to attach to the message, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(KeyType type, String context) {
        return Key.generateKey(type, -1, null, context);
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
        return Key.generateKey(type, validFor, null, null);
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
        return Key.generateKey(type, validFor, issuerId, null);
    }

    /**
     * Will generate a new Key with a specified type, an expiration date, and the identifier of the issuer. Abiding to
     * the expiration date is application specific as the key will continue to function after the expiration date.
     * Providing -1 as validFor will skip setting an expiration date.
     * @param type The type of key to generate.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @param context The context to attach to the message, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(KeyType type, long validFor, UUID issuerId, String context) {
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        Key key = Crypto.generateKey(type);
        if (validFor != -1) {
            key.claims.put(Claim.EXP, key.claims.getInstant(Claim.IAT).plusSeconds(validFor));
        }
        key.claims.put(Claim.ISS, issuerId);
        key.claims.put(Claim.CTX, context);
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
        Key copy = new Key(getUniqueId(), this.getKeyType(), null, getRawPublic());
        copy.claims.put(Claim.IAT, this.claims.getInstant(Claim.IAT));
        copy.claims.put(Claim.EXP, this.claims.getInstant(Claim.EXP));
        copy.claims.put(Claim.ISS, this.claims.getUUID(Claim.ISS));
        copy.claims.put(Claim.CTX, this.claims.get(Claim.CTX));
        return copy;
    }

    /// PACKAGE-PRIVATE ///

    Key() { }

    Key(UUID id, KeyType type, byte[] key, byte[] pub) {
        this.claims = new ClaimsMap(id);
        this.claims.put(Claim.IAT, Utility.createTimestamp());
        if (key != null) {
            this.claims.put(Claim.KEY, Utility.combine(Key.headerFrom(type, KeyVariant.SECRET), key));
        }
        if (pub != null) {
            this.claims.put(Claim.PUB, Utility.combine(Key.headerFrom(type, KeyVariant.PUBLIC), pub));
        }
    }

    /// PACKAGE-PRIVATE ///

    byte[] getRawSecret() {
        if (_rawSecret == null) {
            _rawSecret = claims.getBytes(Claim.KEY);
            if (_rawSecret == null) { return null; }
            _rawSecret = Utility.subArray(_rawSecret, Key.HEADER_SIZE, _rawSecret.length - Key.HEADER_SIZE);
        }
        return _rawSecret;
    }
    private byte[] _rawSecret;

    byte[] getRawPublic() {
        if (_rawPublic == null) {
            _rawPublic = claims.getBytes(Claim.PUB);
            if (_rawPublic == null) { return null; }
            _rawPublic = Utility.subArray(_rawPublic, Key.HEADER_SIZE, _rawPublic.length - Key.HEADER_SIZE);
        }
        return _rawPublic;
    }
    private byte[] _rawPublic;

    /// PROTECTED ///

    protected Key(String base58key) throws DimeFormatException {
        if (base58key != null && base58key.length() > 0) {
            byte[] bytes = Base58.decode(base58key);
            if (bytes.length > 0) {
                switch (Key.getKeyVariant(bytes)) {
                    case SECRET:
                        this.claims = new ClaimsMap();
                        this.claims.put(Claim.KEY, bytes);
                        break;
                    case PUBLIC:
                        this.claims = new ClaimsMap();
                        this.claims.put(Claim.PUB, bytes);
                        break;
                }
                if (this.claims != null) { return; }
            }
        }
        throw new DimeFormatException("Invalid key. (K1010)");
    }

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope.COMPONENT_DELIMITER);
        if (components.length != Key.NBR_EXPECTED_COMPONENTS) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected " + Key.NBR_EXPECTED_COMPONENTS + ", got " + components.length +"."); }
        if (components[Key.TAG_INDEX].compareTo(Key.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + Key.TAG + ", got " + components[Key.TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Key.CLAIMS_INDEX]);
        claims = new ClaimsMap(new String(json, StandardCharsets.UTF_8));
        this.encoded = encoded;
    }

    @Override
    protected String encode() {
        if (this.encoded == null) {
            this.encoded = Key.TAG +
                    Envelope.COMPONENT_DELIMITER +
                    Utility.toBase64(this.claims.toJSON());
        }
        return this.encoded;
    }

    /// PRIVATE ///

    private static final int NBR_EXPECTED_COMPONENTS = 2;
    private static final int TAG_INDEX = 0;
    private static final int CLAIMS_INDEX = 1;
    private static final int HEADER_SIZE = 6;

    private static byte[] headerFrom(KeyType type, KeyVariant variant) {
        AlgorithmFamily algorithmFamily = AlgorithmFamily.keyTypeOf(type);
        byte[] header = new byte[Key.HEADER_SIZE];
        header[0] = (byte)Dime.VERSION;
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
            default:
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
