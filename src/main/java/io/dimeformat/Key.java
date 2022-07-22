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

import io.dimeformat.crypto.ICryptoSuite;
import io.dimeformat.enums.*;
import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeFormatException;

import java.util.List;
import java.util.UUID;
import static java.util.stream.Collectors.toList;

/**
 * Represents cryptographic keys. This may be keys for signing and verifying other Di:ME items and envelopes, used for
 * encryption purposes, or when exchanging shared keys between entities.
 */
public class Key extends Item {

    /// PUBLIC ///

    /**
     * Defines different types of cryptographic keys.
     * Used for header information in keys and when generating new keys.
     */
    public enum Use {

        /**
         * Undefined usage of the key (should not happen).
         */
        UNDEFINED,
        /**
         * Key type for asymmetric key used for signing.
         */
        SIGN,
        /**
         * Key type for asymmetric keys used for key exchange (agreement).
         */
        EXCHANGE,
        /**
         * Key type for symmetric keys used for encryption.
         */
        ENCRYPT;

        /**
         * An intermediate method to convert legacy KeyType to KeyUsage. Should only be used for legacy keys.
         * @param type The KeyType to convert.
         * @return Equivalent KeyUsage.
         */
        @Deprecated
        public static Key.Use fromKeyType(KeyType type) {
            switch (type) {
                case IDENTITY: return Key.Use.SIGN;
                case EXCHANGE: return Key.Use.EXCHANGE;
                case ENCRYPTION: return Key.Use.ENCRYPT;
                case AUTHENTICATION:
                case UNDEFINED:
                default:
                    return Key.Use.UNDEFINED;
            }
        }

    }

    /** The item type identifier for Di:ME Key items. */
    public static final String ITEM_IDENTIFIER = "KEY";

    @Override
    public String getItemIdentifier() {
        return Key.ITEM_IDENTIFIER;
    }

    /**
     * Returns the type of the key. The type determines what the key may be used for, this since it is also closely
     * associated with the cryptographic algorithm the key is generated for.
     * @return The type of the key.
     */
    @Deprecated
    public KeyType getKeyType() {
        if (_type == null) {
            if (isLegacy()) {
                try {
                    String key = getClaims().get(Claim.KEY);
                    if (key == null) {
                        key = getClaims().get(Claim.PUB);
                        decodeKey(key, Claim.PUB);
                    } else {
                        decodeKey(key, Claim.KEY);
                    }
                } catch (DimeCryptographicException e) {
                    throw new IllegalStateException("Invalid legacy key, missing key type.");
                }
            } else {
                if (hasUse(Key.Use.SIGN)) {
                    _type = KeyType.IDENTITY;
                } else if (hasUse(Key.Use.EXCHANGE)) {
                    _type = KeyType.EXCHANGE;
                } else if (hasUse(Key.Use.ENCRYPT)) {
                    _type = KeyType.ENCRYPTION;
                }
            }
        }
        return _type;
    }
    private KeyType _type;

    /**
     * Returns the cryptographic suite used to generate they key.
     * @return Cryptographic suite
     */
    public String getCryptoSuiteName() {
        if (_suiteName == null) {
            if (getKeyBytes(Claim.KEY) == null) {
                // It is ok to ignore return value here as we are looking to force the generation of _suite
                getKeyBytes(Claim.PUB);
            }
        }
        return _suiteName;
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

    /**
     * Returns the raw byte array of the requested key. Valid claims to request are {@link Claim#KEY} and
     * {@link Claim#PUB}.
     * @param claim The key, expressed as a claim, to request bytes of.
     * @return The raw byte array of the key, null if none exists.
     */
    public byte[] getKeyBytes(Claim claim) {
        try {
            if (claim == Claim.KEY) {
                if (this._secretBytes == null) {
                    decodeKey(getClaims().get(Claim.KEY), Claim.KEY);
                }
                return this._secretBytes;
            } else if (claim == Claim.PUB) {
                if (this._publicBytes == null) {
                    decodeKey(getClaims().get(Claim.PUB), Claim.PUB);
                }
                return this._publicBytes;
            } else {
                throw new IllegalArgumentException("Invalid claim for key provided: " + claim);
            }
        } catch (DimeCryptographicException ignored) {
            return null;
        }
    }

    /**
     * Returns a list of cryptographic uses that the key may perform.
     * @return List of usages.
     */
    public List<Key.Use> getUse() {
        if (_use == null) {
            List<String> usage = getClaims().get(Claim.USE);
            if (usage != null) {
                _use = usage.stream().map(cap -> Key.Use.valueOf(cap.toUpperCase())).collect(toList());
            } else {
                // This may be legacy
                getKeyBytes(Claim.PUB);
                getKeyBytes(Claim.KEY);
                _use = List.of(Key.Use.fromKeyType(getKeyType()));
            }
        }
        return _use;
    }

    /**
     * Indicates if a key may be used for a specific cryptographic use.
     * @param use The use to test for.
     * @return True if key supports the use, false otherwise.
     */
    public boolean hasUse(Key.Use use) {
        if (use == null) { return false; }
        return getUse().contains(use);
    }

    /**
     * Will generate a new Key with a specified type.
     * @param type The type of key to generate.
     * @return A newly generated key.
     */
    @Deprecated
    public static Key generateKey(KeyType type) {
        return Key.generateKey(type, -1, null, null);
    }

    /**
     * Will generate a new Key with a specified type.
     * @param type The type of key to generate.
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    @Deprecated
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
    @Deprecated
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
    @Deprecated
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
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    @Deprecated
    public static Key generateKey(KeyType type, long validFor, UUID issuerId, String context) {
        return Key.generateKey(List.of(Key.Use.fromKeyType(type)), validFor, issuerId, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage.
     * @param use The use of the key.
     * @return A newly generated key.
     */
    public static Key generateKey(List<Key.Use> use) {
        return Key.generateKey(use, -1, null, null, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage and attach a specified context.
     * @param use The use of the key.
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(List<Key.Use> use, String context) {
        return Key.generateKey(use, -1, null, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage, an expiration date, and the identifier of the issuer.
     * Abiding to the expiration date is application specific as the key will continue to function after the expiration
     * date. Providing -1 as validFor will skip setting an expiration date. The specified context will be attached to
     * the generated key.
     * @param use The use of the key.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(List<Key.Use> use, long validFor, UUID issuerId, String context) {
        return Key.generateKey(use, validFor, issuerId, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage, an expiration date, and the identifier of the issuer.
     * Abiding to the expiration date is application specific as the key will continue to function after the expiration
     * date. Providing -1 as validFor will skip setting an expiration date. The specified context will be attached to
     * the generated key. The cryptographic suite specified will be used when generating the key.
     * @param use The use of the key.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @param context The context to attach to the key, may be null.
     * @param suiteName A newly generated key.
     * @return A newly generated key.
     */
    public static Key generateKey(List<Key.Use> use, long validFor, UUID issuerId, String context, String suiteName) {
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        try {
            byte[][] keyBytes = Dime.crypto.generateKey(use, suiteName);
            Key key = new Key(UUID.randomUUID(),
                    use,
                    keyBytes[ICryptoSuite.SECRET_KEY_INDEX],
                    keyBytes.length == 2 ? keyBytes[ICryptoSuite.PUBLIC_KEY_INDEX] : null,
                    suiteName);
            if (validFor != -1) {
                key.getClaims().put(Claim.EXP, key.getClaims().getInstant(Claim.IAT).plusSeconds(validFor));
            }
            key.getClaims().put(Claim.UID, UUID.randomUUID());
            key.getClaims().put(Claim.ISS, issuerId);
            key.getClaims().put(Claim.CTX, context);
            return key;
        } catch (DimeCryptographicException e) {
            throw new RuntimeException("Unexpected exception thrown when generating key: " + e);
        }
    }

    /**
     * Will create a copy of a key with only the public part left. This should be used when transmitting a key to
     * another entity, when the receiving entity only needs the public part.
     * @return A new instance of the key with only the public part.
     */
    public Key publicCopy() {
        Key copyKey = new Key(getUse(), null, getPublic(), getCryptoSuiteName());
        copyKey.getClaims().put(Claim.UID, getUniqueId());
        copyKey.getClaims().put(Claim.IAT, getIssuedAt());
        copyKey.getClaims().put(Claim.EXP, getExpiresAt());
        copyKey.getClaims().put(Claim.ISS, getIssuerId());
        copyKey.getClaims().put(Claim.CTX, getContext());
        copyKey.getClaims().put(Claim.USE, getUse().stream().map(aUse -> aUse.name().toLowerCase()).collect(toList()));
        return copyKey;
    }

    /**
     * Generates a shared secret from the current key and another provided key. Both keys must have key usage EXCHANGE
     * specified.
     * @param key The other key to use with the key exchange (generation of shared key).
     * @param use The requested usage of the generated shared key, usually {@link Key.Use#ENCRYPT}.
     * @return The generated shared key.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Key generateSharedSecret(Key key, List<Key.Use> use) throws DimeCryptographicException {
        byte[] sharedKey = Dime.crypto.generateSharedSecret(this, key, use);
        return new Key(UUID.randomUUID(), use, sharedKey, null, getCryptoSuiteName());
    }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Dime envelopes.
     */
    Key() { }

    Key(UUID id, List<Key.Use> use, byte[] key, byte[] pub, String suiteName) {
        getClaims().put(Claim.UID, id);
        getClaims().put(Claim.IAT, Utility.createTimestamp());
        this._suiteName = suiteName;
        this._use = use;
        getClaims().put(Claim.USE, use.stream().map(aUse -> aUse.name().toLowerCase()).collect(toList()));
        if (key != null) {
            getClaims().put(Claim.KEY, Key.encodeKey(suiteName, key));
        }
        if (pub != null) {
            getClaims().put(Claim.PUB, Key.encodeKey(suiteName, pub));
        }
    }

    Key(List<Key.Use> use, String key, String pub, String suiteName) {
        this._suiteName = suiteName;
        this._use = use;
        if (key != null) {
            getClaims().put(Claim.KEY, key);
        }
        if (pub != null) {
            getClaims().put(Claim.PUB, pub);
        }
    }

    Key(List<Key.Use> use, String key, Claim claim) throws DimeCryptographicException {
        this._use = use;
        getClaims().put(claim, key);
        getClaims().remove(Claim.UID); // TODO: rewrite this so that UID is null on creation
    }

    /// PROTECTED ///

    @Override
    protected void customDecoding(List<String> components) throws DimeFormatException {
        if (components.size() > Item.MINIMUM_NBR_COMPONENTS + 1) { throw new DimeFormatException("More components in item then expected, got " + components.size() + ", expected maximum " + (Item.MINIMUM_NBR_COMPONENTS + 1)); }
        this.isSigned = components.size() > Item.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final int CRYPTO_SUITE_INDEX = 0;
    private static final int ENCODED_KEY_INDEX = 1;
    private static final int LEGACY_KEY_HEADER_SIZE = 6;
    private String _suiteName;
    private List<Key.Use> _use;
    private byte[] _secretBytes;
    private byte[] _publicBytes;

    @Deprecated
    private static KeyType getKeyType(byte[] key) {
        AlgorithmFamily family = AlgorithmFamily.valueOf(key[1]);
        switch (family) {
            case AEAD:
                return KeyType.ENCRYPTION;
            case ECDH:
                return KeyType.EXCHANGE;
            case EDDSA:
                return KeyType.IDENTITY;
            case HASH:
                return KeyType.AUTHENTICATION;
            default:
                return KeyType.UNDEFINED;
        }
    }

    @Override
    public void convertToLegacy() {
        if (isLegacy()) { return; }
        Key.convertKeyToLegacy(this, getUse().get(0), Claim.KEY);
        Key.convertKeyToLegacy(this, getUse().get(0), Claim.PUB);
        super.convertToLegacy();
    }

    @Override
    public boolean isLegacy() {
        // Get the keys (if needed) to check if this is legacy
        getKeyBytes(Claim.PUB);
        getKeyBytes(Claim.KEY);
        return super.isLegacy();
    }

    static void convertKeyToLegacy(Item item, Key.Use use, Claim claim) {
        String key = item.getClaims().get(claim);
        if (key == null) { return; }
        byte[] header = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        String b58 = key.substring(key.indexOf(Dime.COMPONENT_DELIMITER) + 1);
        byte[] rawKey = Base58.decode(b58);
        byte[] legacyKey = Utility.combine(header, rawKey);
        legacyKey[1] = use == Key.Use.ENCRYPT ? 0x10 : use == Key.Use.EXCHANGE ? (byte)0x40 : (byte)0x80;
        legacyKey[2] = use == Key.Use.EXCHANGE ? (byte)0x02 : (byte)0x01;
        if (claim == Claim.PUB) {
            legacyKey[3] = 0x01;
        } else if (use == Key.Use.ENCRYPT) {
            legacyKey[3] = 0x02;
        }
        item.getClaims().put(claim, Base58.encode(legacyKey));
    }

    private static String encodeKey(String suiteName, byte[] rawKey) {
        return suiteName + Dime.COMPONENT_DELIMITER + Base58.encode(rawKey);
    }

    private void decodeKey(String encoded, Claim claim) throws DimeCryptographicException {
        if (encoded == null || encoded.isEmpty()) { return; } // Do a silent return, no key to decode
        String[] components = encoded.split("\\" + Dime.COMPONENT_DELIMITER);
        String suiteName;
        boolean legacyKey = false;
        if (components.length == 2) {
            suiteName = components[Key.CRYPTO_SUITE_INDEX].toUpperCase();
        } else {
            // This will be treated as legacy
            suiteName = Dime.STANDARD_SUITE;
            legacyKey = true;
            markAsLegacy();
        }
        if (this._suiteName == null) {
            this._suiteName = suiteName;
        } else if (!this._suiteName.equals(suiteName)) {
            throw new DimeCryptographicException("Public and secret keys generated using different cryptographic suites: " + this._suiteName + " and " + suiteName + ".");
        }
        byte[] rawKey;
        if (!legacyKey) {
            rawKey = Base58.decode(components[Key.ENCODED_KEY_INDEX]);
        } else {
            byte[] decoded = Base58.decode(encoded);
            rawKey = Utility.subArray(decoded, Key.LEGACY_KEY_HEADER_SIZE);
            _type = Key.getKeyType(decoded);
        }
        if (claim == Claim.KEY) {
            this._secretBytes = rawKey;
        } else if (claim == Claim.PUB) {
            this._publicBytes = rawKey;
        } else {
            throw new IllegalArgumentException("Invalid claim provided for key: " + claim);
        }
        if (legacyKey) {
            markAsLegacy();
        }
    }

}
