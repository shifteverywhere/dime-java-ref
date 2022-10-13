//
//  Message.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
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

    /** The item type identifier for Di:ME Message items. */
    public static final String ITEM_IDENTIFIER = "MSG";

    @Override
    public String getItemIdentifier() {
        return Message.ITEM_IDENTIFIER;
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

    @Override
    public String thumbprint() throws CryptographyException {
        if (!isSigned()) { throw new IllegalStateException("Unable to generate thumbprint, must be signed first."); }
        return super.thumbprint();
    }

    /**
     * Will encrypt and attach a payload using a shared encryption key between the issuer and audience of a message.
     * @param payload The payload to encrypt and attach to the message, must not be null and of length 1 or longer.
     * @param issuerKey This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.
     * @param audienceKey This is the key of the audience of the message, must be of type EXCHANGE, must not be null.
     * @throws CryptographyException If something goes wrong.
     */
    public void setPayload(byte[] payload, Key issuerKey, Key audienceKey) throws CryptographyException {
        throwIfSigned();
        if (payload == null || payload.length == 0) { throw new IllegalArgumentException("Unable to set payload, payload must not be null or empty."); }
        if (issuerKey == null) { throw new IllegalArgumentException("Unable to encrypt, issuer key must not be null."); }
        if (audienceKey == null) { throw new IllegalArgumentException("Unable to encrypt, audience key must not be null."); }
        Key sharedKey = issuerKey.generateSharedSecret(audienceKey, List.of(KeyCapability.ENCRYPT));
        setPayload(Dime.crypto.encrypt(payload, sharedKey));
    }

    /**
     * Returns the decrypted message payload, if it is able to decrypt it.
     * @param issuerKey This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.
     * @param audienceKey This is the key of the audience of the message, must be of type EXCHANGE, must not be null.
     * @return The message payload.
     * @throws CryptographyException If something goes wrong.
     */
    public byte[] getPayload(Key issuerKey, Key audienceKey) throws CryptographyException {
        if (issuerKey == null) { throw new IllegalArgumentException("Provided issuer key may not be null."); }
        if (audienceKey == null) { throw new IllegalArgumentException("Provided audience key may not be null."); }
        Key sharedKey = issuerKey.generateSharedSecret(audienceKey, List.of(KeyCapability.ENCRYPT));
        return Dime.crypto.decrypt(getPayload(), sharedKey);
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

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.KID, Claim.MIM, Claim.MTD, Claim.SUB, Claim.SYS, Claim.UID);
    private static final int MINIMUM_NBR_COMPONENTS = 4;

}
