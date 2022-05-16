//
//  Key.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.AlgorithmFamily;
import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyType;
import io.dimeformat.enums.KeyVariant;
import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeFormatException;
import java.util.List;
import java.util.UUID;

/**
 * Represents cryptographic keys. This may be keys for signing and verifying other Di:ME items and envelopes, used for
 * encryption purposes, or when exchanging shared keys between entities.
 */
public class Key extends Item {

    /// PUBLIC ///

    /** The item type identifier for Di:ME Key items. */
    public static final String ITEM_IDENTIFIER = "KEY";

    @Override
    public String getItemIdentifier() {
        return Key.ITEM_IDENTIFIER;
    }

    /**
     * Returns the version of the Di:ME specification for which this key was generated.
     * @return The Di:ME specification version of the key.
     */
    @Deprecated
    public int getVersion() {
        byte[] key = getClaims().getBytes(Claim.KEY);
        if (key == null) { key = getClaims().getBytes(Claim.PUB); }
        return key[0];
    }

    /**
     * Returns the type of the key. The type determines what the key may be used for, this since it is also closely
     * associated with the cryptographic algorithm the key is generated for.
     * @return The type of the key.
     */
    @Deprecated
    public KeyType getKeyType() {
        byte[] key = getClaims().getBytes(Claim.KEY);
        if (key == null) { key = getClaims().getBytes(Claim.PUB); }
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
        return getClaims().get(Claim.KEY);
    }

    /**
     * The public part of the key. This part may be stored or transmitted in plain text.
     * @return A base 58 encoded string.
     */
    public String getPublic() {
        return getClaims().get(Claim.PUB);
    }

    public List<KeyType> getKeyUsage() { return null; }

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
        try {
            Key key = Crypto.generateKey(type);
            if (validFor != -1) {
                key.getClaims().put(Claim.EXP, key.getClaims().getInstant(Claim.IAT).plusSeconds(validFor));
            }
            key.getClaims().put(Claim.ISS, issuerId);
            key.getClaims().put(Claim.CTX, context);
            return key;
        } catch (DimeCryptographicException e) {
            throw new RuntimeException("This should not happen, if it does complain to the author.");
        }
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
        Key copyKey = new Key(getUniqueId(), this.getKeyType(), null, getRawPublic());
        copyKey.getClaims().put(Claim.IAT, getClaims().getInstant(Claim.IAT));
        copyKey.getClaims().put(Claim.EXP, getClaims().getInstant(Claim.EXP));
        copyKey.getClaims().put(Claim.ISS, getClaims().getUUID(Claim.ISS));
        copyKey.getClaims().put(Claim.CTX, getClaims().get(Claim.CTX));
        return copyKey;
    }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Di:ME envelopes.
     */
    Key() { }

    Key(UUID id, KeyType type, byte[] key, byte[] pub) {
        getClaims().put(Claim.UID, id);
        getClaims().put(Claim.IAT, Utility.createTimestamp());
        if (key != null) {
            getClaims().put(Claim.KEY, Utility.combine(Key.headerFrom(type, KeyVariant.SECRET), key));
        }
        if (pub != null) {
            getClaims().put(Claim.PUB, Utility.combine(Key.headerFrom(type, KeyVariant.PUBLIC), pub));
        }
    }

    /// PACKAGE-PRIVATE ///

    byte[] getRawSecret() {
        if (_rawSecret == null) {
            _rawSecret = getClaims().getBytes(Claim.KEY);
            if (_rawSecret == null) { return null; }
            _rawSecret = Utility.subArray(_rawSecret, Key.HEADER_SIZE, _rawSecret.length - Key.HEADER_SIZE);
        }
        return _rawSecret;
    }
    private byte[] _rawSecret;

    byte[] getRawPublic() {
        if (_rawPublic == null) {
            _rawPublic = getClaims().getBytes(Claim.PUB);
            if (_rawPublic == null) { return null; }
            _rawPublic = Utility.subArray(_rawPublic, Key.HEADER_SIZE, _rawPublic.length - Key.HEADER_SIZE);
        }
        return _rawPublic;
    }
    private byte[] _rawPublic;

    /// PROTECTED ///

    protected Key(String base58key) {
        if (base58key != null && base58key.length() > 0) {
            byte[] bytes = Base58.decode(base58key);
            if (bytes.length > 0) {
                switch (Key.getKeyVariant(bytes)) {
                    case SECRET:
                        getClaims().put(Claim.KEY, bytes);
                        break;
                    case PUBLIC:
                        getClaims().put(Claim.PUB, bytes);
                        break;
                }
            }
        }
    }

    /// PRIVATE ///

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
