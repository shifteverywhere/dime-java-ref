//
//  Key.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.crypto.ICryptoSuite;
import io.dimeformat.enums.*;
import io.dimeformat.exceptions.CryptographyException;
import io.dimeformat.exceptions.InvalidFormatException;
import java.time.Instant;
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
        return getClaim(Claim.KEY);
    }

    /**
     * The public part of the key. This part may be stored or transmitted in plain text.
     * @return A base 58 encoded string.
     */
    public String getPublic() {
        return getClaim(Claim.PUB);
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
                    decodeKey(getClaim(Claim.KEY), Claim.KEY);
                }
                return this._secretBytes;
            } else if (claim == Claim.PUB) {
                if (this._publicBytes == null) {
                    decodeKey(getClaim(Claim.PUB), Claim.PUB);
                }
                return this._publicBytes;
            } else {
                throw new IllegalArgumentException("Invalid claim for key provided: " + claim);
            }
        } catch (CryptographyException ignored) {
            return null;
        }
    }

    /**
     * Returns a list of cryptographic capabilities that the key may perform.
     * @return List of capabilities.
     */
    public List<KeyCapability> getCapability() {
        if (_capabilities == null) {
            List<String> caps = getClaim(Claim.CAP);
            if (caps != null) {
                _capabilities = caps.stream().map(cap -> KeyCapability.valueOf(cap.toUpperCase())).collect(toList());
            } else {
                // This may be legacy
                getKeyBytes(Claim.PUB);
                getKeyBytes(Claim.KEY);
            }
        }
        return _capabilities;
    }

    /**
     * Indicates if a key may be used for a specific cryptographic capability.
     * @param capability The capability to test for.
     * @return True if key supports the use, false otherwise.
     */
    public boolean hasCapability(KeyCapability capability) {
        if (capability == null) { return false; }
        return getCapability().contains(capability);
    }

    /**
     * Will generate a new key for a specific cryptographic capability.
     * @param capability The capability of the key.
     * @return A newly generated key.
     */
    public static Key generateKey(KeyCapability capability) {
        return Key.generateKey(List.of(capability), Dime.NO_EXPIRATION, null, null, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new key for a specific cryptographic capabilities.
     * @param capabilities The capabilities of the key.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyCapability> capabilities) {
        return Key.generateKey(capabilities, Dime.NO_EXPIRATION, null, null, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new key for a specific cryptographic capabilities and setting a context to the key.
     * @param capabilities The capabilities of the key.
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyCapability> capabilities, String context) {
        return Key.generateKey(capabilities, Dime.NO_EXPIRATION, null, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new key for a specific cryptographic capabilities, an expiration date, and the identifier of the issuer.
     * Abiding to the expiration date is application specific as the key will continue to function after the expiration
     * date. Providing {@link Dime#NO_EXPIRATION} as validFor will skip setting an expiration date. The specified context will be attached to
     * the generated key.
     * @param capabilities The capabilities of the key.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @param context The context to attach to the key, may be null.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyCapability> capabilities, long validFor, UUID issuerId, String context) {
        return Key.generateKey(capabilities, validFor, issuerId, context, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Will generate a new key for a specific cryptographic capabilities, an expiration date, and the identifier of the issuer.
     * Abiding to the expiration date is application specific as the key will continue to function after the expiration
     * date. Providing {@link Dime#NO_EXPIRATION} as validFor will skip setting an expiration date. The specified context will be attached to
     * the generated key. The cryptographic suite specified will be used when generating the key.
     * @param capabilities The capabilities of the key.
     * @param validFor The number of seconds that the key should be valid for, from the time of issuing.
     * @param issuerId The identifier of the issuer (creator) of the key, may be null.
     * @param context The context to attach to the key, may be null.
     * @param suiteName The name of the cryptographic suite to use, if null, then the default suite will be used.
     * @return A newly generated key.
     */
    public static Key generateKey(List<KeyCapability> capabilities, long validFor, UUID issuerId, String context, String suiteName) {
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        try {
            byte[][] keyBytes = Dime.crypto.generateKey(capabilities, suiteName);
            Key key = new Key(UUID.randomUUID(),
                    capabilities,
                    keyBytes[ICryptoSuite.SECRET_KEY_INDEX],
                    keyBytes.length == 2 ? keyBytes[ICryptoSuite.PUBLIC_KEY_INDEX] : null,
                    suiteName);
            if (validFor != -1) {
                key.setClaimValue(Claim.EXP, ((Instant) key.getClaim(Claim.IAT)).plusSeconds(validFor));
            }
            key.setClaimValue(Claim.ISS, issuerId);
            key.setClaimValue(Claim.CTX, context);
            return key;
        } catch (CryptographyException e) {
            throw new RuntimeException("Unexpected exception thrown when generating key: " + e);
        }
    }

    /**
     * Will create a copy of a key with only the public part left. This should be used when transmitting a key to
     * another entity, when the receiving entity only needs the public part.
     * @return A new instance of the key with only the public part.
     */
    public Key publicCopy() {
        Key copyKey = new Key(getCapability(), null, getPublic(), getCryptoSuiteName());
        copyKey.setClaimValue(Claim.UID, getClaim(Claim.UID));
        copyKey.setClaimValue(Claim.IAT, getClaim(Claim.IAT));
        copyKey.setClaimValue(Claim.EXP, getClaim(Claim.EXP));
        copyKey.setClaimValue(Claim.ISS, getClaim(Claim.ISS));
        copyKey.setClaimValue(Claim.CTX, getClaim(Claim.CTX));
        copyKey.setClaimValue(Claim.CAP, getCapability().stream().map(aUse -> aUse.name().toLowerCase()).collect(toList()));
        return copyKey;
    }

    /**
     * Generates a shared secret from the current key and another provided key. Both keys must have key usage EXCHANGE
     * specified.
     * @param key The other key to use with the key exchange (generation of shared key).
     * @param capabilities The requested capabilities of the generated shared key, usually {@link KeyCapability#ENCRYPT}.
     * @return The generated shared key.
     * @throws CryptographyException If anything goes wrong.
     */
    public Key generateSharedSecret(Key key, List<KeyCapability> capabilities) throws CryptographyException {
        byte[] sharedKey = Dime.crypto.generateSharedSecret(this, key, capabilities);
        return new Key(UUID.randomUUID(), capabilities, sharedKey, null, getCryptoSuiteName());
    }

    @Override
    public void convertToLegacy() {
        if (isLegacy()) { return; }
        Key.convertKeyToLegacy(this, getCapability().get(0), Claim.KEY);
        Key.convertKeyToLegacy(this, getCapability().get(0), Claim.PUB);
        super.convertToLegacy();
    }

    @Override
    public boolean isLegacy() {
        // Get the keys (if needed) to check if this is legacy
        getKeyBytes(Claim.PUB);
        getKeyBytes(Claim.KEY);
        return super.isLegacy();
    }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Dime envelopes.
     */
    Key() { }

    Key(UUID id, List<KeyCapability> use, byte[] key, byte[] pub, String suiteName) {
        setClaimValue(Claim.UID, id);
        setClaimValue(Claim.IAT, Utility.createTimestamp());
        this._suiteName = suiteName;
        this._capabilities = use;
        setClaimValue(Claim.CAP, use.stream().map(aUse -> aUse.name().toLowerCase()).collect(toList()));
        if (key != null) {
            setClaimValue(Claim.KEY, Key.encodeKey(suiteName, key));
        }
        if (pub != null) {
            setClaimValue(Claim.PUB, Key.encodeKey(suiteName, pub));
        }
    }

    Key(List<KeyCapability> capabilities, String key, String pub, String suiteName) {
        this._suiteName = suiteName;
        this._capabilities = capabilities;
        if (key != null) {
            setClaimValue(Claim.KEY, key);
        }
        if (pub != null) {
            setClaimValue(Claim.PUB, pub);
        }
    }

    Key(List<KeyCapability> capabilities, String key, Claim claim) throws CryptographyException {
        this._capabilities = capabilities;
        setClaimValue(claim, key);
    }

    static void convertKeyToLegacy(Item item, KeyCapability capability, Claim claim) {
        String key = item.getClaim(claim);
        if (key == null) { return; }
        byte[] header = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        String b58 = key.substring(key.indexOf(Dime.COMPONENT_DELIMITER) + 1);
        byte[] rawKey = Base58.decode(b58);
        byte[] legacyKey = Utility.combine(header, rawKey);
        legacyKey[1] = capability == KeyCapability.ENCRYPT ? 0x10 : capability == KeyCapability.EXCHANGE ? (byte)0x40 : (byte)0x80;
        legacyKey[2] = capability == KeyCapability.EXCHANGE ? (byte)0x02 : (byte)0x01;
        if (claim == Claim.PUB) {
            legacyKey[3] = 0x01;
        } else if (capability == KeyCapability.ENCRYPT) {
            legacyKey[3] = 0x02;
        }
        item.setClaimValue(claim, Base58.encode(legacyKey));
    }

    /// PROTECTED ///

    @Override
    protected boolean allowedToSetClaimDirectly(Claim claim) {
        return Key.allowedClaims.contains(claim);
    }

    @Override
    protected void customDecoding(List<String> components) throws InvalidFormatException {
        if (components.size() > Item.MINIMUM_NBR_COMPONENTS + 1) { throw new InvalidFormatException("More components in item than expected, got " + components.size() + ", expected maximum " + (Item.MINIMUM_NBR_COMPONENTS + 1)); }
        this.isSigned = components.size() > Item.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.KID, Claim.MTD, Claim.SUB, Claim.SYS, Claim.UID);
    private static final int CRYPTO_SUITE_INDEX = 0;
    private static final int ENCODED_KEY_INDEX = 1;
    private static final int LEGACY_KEY_HEADER_SIZE = 6;
    private String _suiteName;
    private List<KeyCapability> _capabilities;
    private byte[] _secretBytes;
    private byte[] _publicBytes;

    @Deprecated
    private static KeyCapability getCapabilityFromLegacy(byte[] key) {
        switch (key[1]) {
            case 0x10: return KeyCapability.keyCapabilityFromLegacy("encryption");
            case 0x40: return KeyCapability.keyCapabilityFromLegacy("exchange");
            case (byte)0x80: return KeyCapability.keyCapabilityFromLegacy("identity");
            case (byte)0xE0: return KeyCapability.keyCapabilityFromLegacy("authenticate");
            default: return null;
        }
    }

    private static String encodeKey(String suiteName, byte[] rawKey) {
        return suiteName + Dime.COMPONENT_DELIMITER + Base58.encode(rawKey);
    }

    private void decodeKey(String encoded, Claim claim) throws CryptographyException {
        if (encoded == null || encoded.isEmpty()) { return; } // Do a silent return, no key to decode
        String[] components = encoded.split("\\" + Dime.COMPONENT_DELIMITER);
        String suiteName;
        boolean legacyKey = false;
        if (components.length == 2) {
            suiteName = components[Key.CRYPTO_SUITE_INDEX].toUpperCase();
        } else {
            // This will be treated as legacy
            suiteName = Dime.crypto.getDefaultSuiteName();
            legacyKey = true;
            markAsLegacy();
        }
        if (this._suiteName == null) {
            this._suiteName = suiteName;
        } else if (!this._suiteName.equals(suiteName)) {
            throw new CryptographyException("Public and secret keys generated using different cryptographic suites: " + this._suiteName + " and " + suiteName + ".");
        }
        byte[] rawKey;
        if (!legacyKey) {
            rawKey = Base58.decode(components[Key.ENCODED_KEY_INDEX]);
        } else {
            byte[] decoded = Base58.decode(encoded);
            rawKey = Utility.subArray(decoded, Key.LEGACY_KEY_HEADER_SIZE);
            KeyCapability cap = Key.getCapabilityFromLegacy(decoded);
            if (cap == null) { throw new IllegalStateException("Invalid key capability encountered."); }
            _capabilities = List.of(cap);
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
