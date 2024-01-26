//
//  Message.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.exceptions.*;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * A class that can be used to create secure and integrity protected messages, that can be sent to entities, who may
 * verify the integrity and trust of the message. Messages may also be end-to-end encrypted to protect the
 * confidentiality of the message payload.
 */
public class Message extends Data {

    /// PUBLIC ///

    /** The item header for DiME Message items. */
    public static final String HEADER = "MSG";

    @Override
    public String getHeader() {
        return Message.HEADER;
    }

    /**
     * Returns a public key that was included in the message. Normally this public key was used for a key exchange where
     * the shared key was used to encrypt the payload. This is optional.
     * @return A public key.
     */
    public Key getPublicKey() {
        String pub = getClaim(Claim.PUB);
        if (pub != null && pub.length() > 0) {
            try {
                return new Key(List.of(KeyCapability.EXCHANGE), pub, Claim.PUB);
            } catch (CryptographyException ignored) { /* ignored */ }
        }
        return null;
    }

    /**
     * Sets a public key that will be included in the message. This may be a public key that was used to derive a shared
     * key used for encrypting the payload. This is optional.
     * @param publicKey The public key to set.
     */
    public void setPublicKey(Key publicKey) {
        if (publicKey != null) {
            throwIfSigned();
            setClaimValue(Claim.PUB, publicKey.getPublic());
        } else {
            removeClaim(Claim.PUB);
        }
    }

    /**
     * Creates a message from a specified issuer (sender).
     * @param issuerId The issuer identifier.
     */
    public Message(UUID issuerId) {
        this(null, issuerId, -1, null);
    }

    /**
     * Creates a message from a specified issuer (sender) and an expiration date.
     * @param issuerId The issuer identifier.
     * @param validFor The number of seconds that the message should be valid for, from the time of issuing.
     */
    public Message(UUID issuerId, long validFor) {
        this(null, issuerId, validFor, null);
    }

    /**
     * Creates a message to a specified audience (receiver) from a specified issuer (sender).
     * @param audienceId The audience identifier. Providing -1 as validFor will skip setting an expiration date.
     * @param issuerId The issuer identifier.
     */
    public Message(UUID audienceId, UUID issuerId) {
        this(audienceId, issuerId, -1, null);
    }

    /**
     * Creates a message to a specified audience (receiver) from a specified issuer (sender), with an expiration date.
     * @param audienceId The audience identifier. Providing -1 as validFor will skip setting an expiration date.
     * @param issuerId The issuer identifier.
     * @param validFor The number of seconds that the message should be valid for, from the time of issuing.
     */
    public Message(UUID audienceId, UUID issuerId, long validFor) {
        this(audienceId, issuerId, validFor, null);
    }

    /**
     * Creates a message to a specified audience (receiver) from a specified issuer (sender), with an expiration date
     * and a context. The context may be anything and may be used for application specific purposes.
     * @param audienceId The audience identifier. Providing -1 as validFor will skip setting an expiration date.
     * @param issuerId The issuer identifier.
     * @param validFor The number of seconds that the message should be valid for, from the time of issuing.
     * @param context The context to attach to the message, may be null.
     */
    public Message(UUID audienceId, UUID issuerId, long validFor, String context) {
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        Instant iat = Utility.createTimestamp();
        Instant exp = (validFor != -1) ? iat.plusSeconds(validFor) : null;
        setClaimValue(Claim.UID, UUID.randomUUID());
        setClaimValue(Claim.AUD, audienceId);
        setClaimValue(Claim.ISS, issuerId);
        setClaimValue(Claim.IAT, iat);
        setClaimValue(Claim.EXP, exp);
        setClaimValue(Claim.CTX, context);
    }

    /**
     * Will encrypt and attach a payload using a shared encryption key generated from the provided keys. The two keys
     * provided must not be null and only one must contain a secret (private) key, the order does not matter.
     * @param payload The payload to encrypt and attach to the message, must not be null and of length 1 or longer.
     * @param firstKey The first key to use, must have capability EXCHANGE, must not be null.
     * @param secondKey The second key to use, must have capability EXCHANGE, must not be null.
     * @throws CryptographyException If something goes wrong.
     */
    public void setPayload(byte[] payload, Key firstKey, Key secondKey) throws CryptographyException {
        throwIfSigned();
        if (payload == null || payload.length == 0) { throw new IllegalArgumentException("Unable to set payload, payload must not be null or empty."); }
        if (firstKey == null || secondKey == null) { throw new IllegalArgumentException("Unable to set payload, both keys must be of a non-null value."); }
        if (firstKey.getSecret() != null && secondKey.getSecret() != null) { throw new IllegalArgumentException("Unable to set payload, both keys must not contain a secret (private) key."); }
        Key primaryKey = firstKey.getSecret() != null ? firstKey : secondKey;
        Key secondaryKey = secondKey.getSecret() == null ? secondKey : firstKey;
        Key sharedKey = primaryKey.generateSharedSecret(secondaryKey, List.of(KeyCapability.ENCRYPT));
        setPayload(Dime.crypto.encrypt(payload, sharedKey));
    }

    /**
     * Will encrypt and attach a payload using the private key. The provided key may either have the capability EXCHANGE
     * or ENCRYPT. If EXCHANGE is used, then a second key will be generated and then used to generate a shared
     * encryption key with the provided key. The public key of the generated EXCHANGE key will be set in the "pub" claim
     * ({@link #getPublicKey()}), but also returned.
     * If a key with capability ENCRYPT is used, then the payload will be encrypted with this key. This key will then be
     * returned. The unique id of the encryption key will be set in the key id ("kid") claim.
     * @param payload The payload to encrypt and attach to the message, must not be null and of length 1 or longer.
     * @param key A key to either use for generating a shared key (EXCHANGE) or encrypting the message directly (ENCRYPT).
     * @return The generated EXCHANGE key, or the encryption key (if provided key had capability ENCRYPT).
     * @throws CryptographyException If something goes wrong.
     */
    public Key setPayload(byte[] payload, Key key) throws CryptographyException {
        if (key == null) { throw new NullPointerException("Unable to set payload, key must not be null"); }
        if (key.hasCapability(KeyCapability.EXCHANGE)) {
            if (key.getSecret() != null) { throw new IllegalArgumentException("Unable to set payload, key should not contain a secret (or private) key."); }
            Key firstKey = Key.generateKey(KeyCapability.EXCHANGE);
            setPayload(payload, firstKey, key);
            setPublicKey(firstKey.publicCopy());
            return firstKey;
        } else if (key.hasCapability(KeyCapability.ENCRYPT)) {
            setPayload(Dime.crypto.encrypt(payload, key));
            putClaim(Claim.KID, key.getClaim(Claim.UID));
            return key;
        }
        throw new CryptographyException("Key capability mismatch.");
    }

    /**
     * Returns the decrypted message payload, if it is able to decrypt it. Two keys must be provided, where only one of
     * the keys may contain a secret (private), the order does not matter. The keys provided must be the same as when
     * used {@link #setPayload(byte[], Key, Key)} or equivalent, although it may be the opposite pair of public and
     * public/secret.
     * @param firstKey The first key to use, must be of type EXCHANGE, must not be null.
     * @param secondKey The second key to use, must be of type EXCHANGE, must not be null.
     * @return The decrypted message payload.
     * @throws CryptographyException If something goes wrong.
     */
    public byte[] getPayload(Key firstKey, Key secondKey) throws CryptographyException {
        if (firstKey == null || secondKey == null) { throw new IllegalArgumentException("Unable to get payload, both keys must be of a non-null value."); }
        if (firstKey.getSecret() != null && secondKey.getSecret() != null) { throw new IllegalArgumentException("Unable to get payload, both keys must not contain a secret (private) key."); }
        Key primaryKey = firstKey.getSecret() != null ? firstKey : secondKey;
        Key secondaryKey = secondKey.getSecret() == null ? secondKey : firstKey;
        try {
            Key sharedKey = secondaryKey.generateSharedSecret(primaryKey, List.of(KeyCapability.ENCRYPT));
            return Dime.crypto.decrypt(getPayload(), sharedKey);
        } catch (CryptographyException e) { /* ignored */ }
        Key sharedKey = primaryKey.generateSharedSecret(secondaryKey, List.of(KeyCapability.ENCRYPT));
        return Dime.crypto.decrypt(getPayload(), sharedKey);
    }

    /**
     * Returns the decrypted message payload, if it is able to decrypt it. The provided key may either have the
     * capability EXCHANGE or ENCRYPT. If EXCHANGE is used, then the "pub" claim will be used as a source for the second
     * exchange key to use when generating a shared encryption key.
     * If the key has capability ENCRYPT, then the payload will be decrypted using the provided key directly.
     * @param key A key to either use for generating a shared key (EXCHANGE) or decrypting the message directly (ENCRYPT).
     * @return The decrypted message payload.
     * @throws CryptographyException If something goes wrong.
     */
    public byte[] getPayload(Key key) throws CryptographyException {
        if (key == null) { throw new NullPointerException("Unable to get payload, key must not be null"); }
        if (key.hasCapability(KeyCapability.EXCHANGE)) {
            if (getClaim(Claim.PUB) == null) { throw new IllegalStateException("Unable to get payload, no public key attached to message."); }
            return getPayload(getPublicKey(), key);
        } else if (key.hasCapability(KeyCapability.ENCRYPT)) {
            return Dime.crypto.decrypt(getPayload(), key);
        }
        throw new CryptographyException("Key capability mismatch.");
    }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Di:ME envelopes.
     */
    Message() { }

    /// PROTECTED ///

    @Override
    protected boolean allowedToSetClaimDirectly(Claim claim) {
        return Message.allowedClaims.contains(claim);
    }

    @Override
    protected String forExport() throws InvalidFormatException {
        if (!isSigned()) { throw new IllegalStateException("Unable to encode message, must be signed first."); }
        return super.forExport();
    }

    @Override
    protected void customDecoding(List<String> components) throws InvalidFormatException {
       super.customDecoding(components);
       this.isSigned = true; // Messages are always signed
    }

    @Override
    protected int getMinNbrOfComponents() {
        return Message.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CMN, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.ISU, Claim.KID, Claim.MIM, Claim.MTD, Claim.SUB, Claim.SYS, Claim.UID);
    private static final int MINIMUM_NBR_COMPONENTS = 4;

}
