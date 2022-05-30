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

import io.dimeformat.enums.*;
import io.dimeformat.exceptions.DimeCryptographicException;
import java.util.List;
import java.util.UUID;
import static java.util.stream.Collectors.toList;

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
        return 1;
    }

    /**
     * Returns the type of the key. The type determines what the key may be used for, this since it is also closely
     * associated with the cryptographic algorithm the key is generated for.
     * @return The type of the key.
     */
    @Deprecated
    public KeyType getKeyType() {
        if (_type == null) {
            if (!getCryptoSuiteName().equals(Dime.LEGACY_SUITE)) { // This will force key decode
                if (hasUsage(KeyUsage.SIGN)) {
                    return KeyType.IDENTITY;
                } else if (hasUsage(KeyUsage.EXCHANGE)) {
                    return KeyType.EXCHANGE;
                } else if (hasUsage(KeyUsage.ENCRYPT)) {
                    return KeyType.ENCRYPTION;
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
            if (getRawSecret() == null) {
                // It is ok to ignore return value here as we are looking to force the generation of _suite
                getRawPublic();
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
     * Returns a list of cryptographic usages that the key may perform.
     * @return List of usages.
     */
    public List<KeyUsage> getKeyUsage() {
        if (_usage == null) {
            if (getCryptoSuiteName().equals(Dime.LEGACY_SUITE)) {
                _usage = List.of(KeyUsage.fromKeyType(getKeyType()));
            } else {
                List<String> usage = getClaims().get(Claim.USE);
                _usage = usage.stream().map(cap -> KeyUsage.valueOf(cap.toUpperCase())).collect(toList());
            }
        }
        return _usage;
    }

    /**
     * Indicates if a key may be used for a specific cryptographic usage.
     * @param usage The usage to test for.
     * @return True if key supports the usage, false otherwise.
     */
    public boolean hasUsage(KeyUsage usage) {
        if (usage == null) { return false; }
        return getKeyUsage().contains(usage);
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
        return Key.generateKey(List.of(KeyUsage.fromKeyType(type)), validFor, issuerId, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage.
     * @param usage The usage of the key.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyUsage> usage) {
        return Key.generateKey(usage, -1, null, null, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage and attach a specfied context.
     * @param usage The usage of the key.
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyUsage> usage, String context) {
        return Key.generateKey(usage, -1, null, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage, an expiration date, and the identifier of the issuer.
     * Abiding to the expiration date is application specific as the key will continue to function after the expiration
     * date. Providing -1 as validFor will skip setting an expiration date. The specified context will be attached to
     * the generated key.
     * @param usage The usage of the key.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyUsage> usage, long validFor, UUID issuerId, String context) {
        return Key.generateKey(usage, validFor, issuerId, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new Key for a specific cryptographic usage, an expiration date, and the identifier of the issuer.
     * Abiding to the expiration date is application specific as the key will continue to function after the expiration
     * date. Providing -1 as validFor will skip setting an expiration date. The specified context will be attached to
     * the generated key. The cryptographic suite specified will be used when generating the key.
     * @param usage The usage of the key.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @param context The context to attach to the key, may be null.
     * @param suiteName A newly generated key.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyUsage> usage, long validFor, UUID issuerId, String context, String suiteName) {
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        try {
            Key key = Dime.crypto.generateKey(usage, suiteName);
            if (validFor != -1) {
                key.getClaims().put(Claim.EXP, key.getClaims().getInstant(Claim.IAT).plusSeconds(validFor));
            }
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
        Key copyKey = new Key(getKeyUsage(), null, getPublic(), getCryptoSuiteName());
        copyKey.getClaims().put(Claim.UID, getUniqueId());
        copyKey.getClaims().put(Claim.IAT, getIssuedAt());
        copyKey.getClaims().put(Claim.EXP, getExpiresAt());
        copyKey.getClaims().put(Claim.ISS, getIssuerId());
        copyKey.getClaims().put(Claim.CTX, getContext());
        return copyKey;
    }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Dime envelopes.
     */
    Key() { }

    Key(UUID id, List<KeyUsage> usage, byte[] key, byte[] pub, String suiteName) {
        getClaims().put(Claim.UID, id);
        getClaims().put(Claim.IAT, Utility.createTimestamp());
        this._suiteName = suiteName;
        this._usage = usage;
        getClaims().put(Claim.USE, usage.stream().map(use -> use.name().toLowerCase()).collect(toList()));
        if (key != null) {
            getClaims().put(Claim.KEY, Key.encodeKey(suiteName, key));
        }
        if (pub != null) {
            getClaims().put(Claim.PUB, Key.encodeKey(suiteName, pub));
        }
    }

    Key(List<KeyUsage> usage, String key, String pub, String suiteName) {
        this._suiteName = suiteName;
        this._usage = usage;
        if (key != null) {
            getClaims().put(Claim.KEY, key);
        }
        if (pub != null) {
            getClaims().put(Claim.PUB, pub);
        }
    }

    Key(List<KeyUsage> usage, String key, Claim claim) throws DimeCryptographicException {
        this._usage = usage;
        getClaims().put(claim, key);
        getClaims().remove(Claim.UID); // TODO: rewrite this so that UID is null on creation
    }

    byte[] getRawSecret() {
        if (this._rawSecret == null) {
            try {
                decodeKey(getClaims().get(Claim.KEY), Claim.KEY);
            } catch (DimeCryptographicException ignored) { /* ignored */ }
        }
        return this._rawSecret;
    }

    byte[] getRawPublic() {
        if (this._rawPublic == null) {
            try {
                decodeKey(getClaims().get(Claim.PUB), Claim.PUB);
            } catch (DimeCryptographicException ignored) { /* ignored */ }
        }
        return this._rawPublic;
    }

    /// PRIVATE ///

    private static final int CRYPTO_SUITE_INDEX = 0;
    private static final int ENCODED_KEY_INDEX = 1;
    private static final int LEGACY_KEY_HEADER_SIZE = 6;
    private String _suiteName;
    private List<KeyUsage> _usage;
    private byte[] _rawSecret;
    private byte[] _rawPublic;

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

    private static String encodeKey(String suiteName, byte[] rawKey) {
        return suiteName + "+" + Base58.encode(rawKey, null);
    }

    private void decodeKey(String encoded, Claim claim) throws DimeCryptographicException {
        if (encoded == null || encoded.isEmpty()) { return; } // Do a silent return, no key to decode
        String[] components = encoded.split("\\+");
        String suiteName;
        if (components.length == 2) {
            suiteName = components[Key.CRYPTO_SUITE_INDEX].toUpperCase();
        } else { // This will be treated as legacy
            suiteName = Dime.LEGACY_SUITE;
        }
        if (this._suiteName == null) {
            this._suiteName = suiteName;
        } else if (!this._suiteName.equals(suiteName)) {
            throw new DimeCryptographicException("Public and secret keys generated using different cryptographic suites: " + this._suiteName + " and " + suiteName + ".");
        }
        byte[] rawKey;
        if (!suiteName.equals(Dime.LEGACY_SUITE)) {
            rawKey = Base58.decode(components[Key.ENCODED_KEY_INDEX]);
        } else {
            byte[] decoded = Base58.decode(encoded);
            rawKey = Utility.subArray(decoded, Key.LEGACY_KEY_HEADER_SIZE);
            _type = Key.getKeyType(decoded);
        }
        if (claim == Claim.KEY) {
            this._rawSecret = rawKey;
        } else if (claim == Claim.PUB) {
            this._rawPublic = rawKey;
        } else {
            throw new IllegalArgumentException("Invalid claim provided for key: " + claim);
        }
    }

}
