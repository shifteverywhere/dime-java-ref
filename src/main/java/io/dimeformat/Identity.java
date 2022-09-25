//
//  Identity.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Capability;
import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

/**
 * Represents an entity inside a network, or equivalent system. May be self-issued or issued by a trusted entity (and
 * thus becomes part of a trusted chain).
 */
public class Identity extends Item {

    /// PUBLIC ///

    /** The item type identifier for Di:ME Identity items. */
    public static final String ITEM_IDENTIFIER = "ID";

    @Override
    public String getItemIdentifier() {
        return Identity.ITEM_IDENTIFIER;
    }

    /**
     * Returns the name of the system or network that the entity belongs to. If issued by another entity and part of a
     * trust chain, then all entities will share the same system name.
     * @return The system name
     */
    public String getSystemName() {
        return getClaims().get(Claim.SYS);
    }

    /**
     * Returns the entity's subject identifier. This is, within the system, defined by system name, unique for one
     * specific entity.
     * @return The subject identifier assigned to an entity, as a UUID.
     */
    public UUID getSubjectId() {
        return getClaims().getUUID(Claim.SUB);
    }

    /**
     * Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
     * public key or type IDENTITY.
     * @return A Key instance with a public key of type IDENTITY.
     */
    public Key getPublicKey() {
        if (_publicKey == null) {
            _publicKey = getClaims().getKey(Claim.PUB, List.of(Key.Use.SIGN));
        }
        return _publicKey;
    }
    private Key _publicKey;

    /**
     * Returns a list of any capabilities given to an identity. These are requested by an entity and approved (and
     * potentially modified) by the issuing entity when issuing a new identity. Capabilities are usually used to
     * determine what an entity may do with its issued identity.
     * @return An immutable list of Capability instances.
     */
    public List<Capability> getCapabilities() {
        if (_capabilities == null) {
            List<String> caps = getClaims().get(Claim.CAP);
            _capabilities = caps.stream().map(cap -> Capability.valueOf(cap.toUpperCase())).collect(toList());
        }
        return _capabilities;
    }
    private List<Capability> _capabilities;

    /**
     * Returns all principles assigned to an identity. These are key-value fields that further provide information about
     * the entity. Using principles are optional.
     * @return An immutable map of assigned principles (as <String, Object>).
     */
    public Map<String, Object> getPrinciples() {
        if (_principles == null) {
            Map<String, Object> pri = getClaims().get(Claim.PRI);
            if (pri != null) {
                _principles = Collections.unmodifiableMap(pri);
            }
        }
        return _principles;
    }
    private Map<String, Object> _principles;

    /**
     * Returns an ambit list assigned to an identity. An ambit defines the scope, region or role where an identity
     * may be used.
     * @return An immutable ambit list (as String instances).
     * @deprecated Will be removed in a future release, use {{@link #getAmbitList()}} instead.
     */
    @Deprecated
    public List<String> getAmbits() {
        return getClaims().get(Claim.AMB);
    }

    /**
     * Returns an ambit list assigned to an identity. An ambit defines the scope, region or role where an identity
     * may be used.
     * @return An immutable ambit list (as String instances).
     */
    public List<String> getAmbitList() {
        return getClaims().get(Claim.AMB);
    }

    /**
     * Returns a list of methods associated with an identity. The usage of this is normally context or application
     * specific, and may specify different methods that can be used convert, transfer or further process a Di:ME
     * identity.
     * @return An immutable list of methods (as String instances).
     */
    public List<String> getMethods() {
        return getClaims().get(Claim.MTD);
    }

    /**
     * Returns the parent identity of a trust chain for an identity. This is the issuing identity.
     * @return Parent identity in a trust chain.
     */
    public Identity getTrustChain() {
        return this.trustChain;
    }

    /**
     * Returns if the identity has been self-issued. Self-issuing happens when the same entity issues its own identity.
     * @return true or false
     */
    public boolean isSelfIssued() {
        return getSubjectId().compareTo(getIssuerId()) == 0 && hasCapability(Capability.SELF);
    }

    /**
     * Returns the currently set trusted identity. This is normally the root identity of a trust chain.
     * @return An Identity instance.
     * @deprecated Will be removed in the future, use {#{@link Dime#getTrustedIdentity()}} instead.
     */
    @Deprecated
    public static synchronized Identity getTrustedIdentity() {
        return Dime.getTrustedIdentity();
    }

    /**
     * Sets an Identity instance to be the trusted identity used for verifying a trust chain of other Identity
     * instances. This is normally the root identity of a trust chain.
     * @param trustedIdentity The Identity instance to set as a trusted identity.
     * @deprecated Will be removed in the future, use {#{@link Dime#setTrustedIdentity(Identity)}} instead.
     */
    @Deprecated
    public static synchronized void setTrustedIdentity(Identity trustedIdentity) {
        Dime.setTrustedIdentity(trustedIdentity);
    }

    /**
     * Verifies if an Identity instance is valid and can be trusted. Will validate issued at and expires at dates, look
     * at a trust chain (if present) and verify the signature with the attached public key.
     * @throws DimeDateException If the issued at date is in the future, or if the expires at date is in the past.
     * @throws DimeUntrustedIdentityException If the trust of the identity could not be verified.
     * @deprecated This method is deprecated since 1.0.1 and will be removed in a future version use
     * {@link #isTrusted()} or {@link #isTrusted(Identity)} instead.
     */
    @Deprecated
    public void verifyTrust() throws DimeDateException, DimeUntrustedIdentityException {
        if (!isTrusted()) {
            throw new DimeUntrustedIdentityException("Unable to verify trust of entity.");
        }
    }

    /**
     * Will verify if an identity can be trusted using the globally set Trusted Identity
     * ({@link #setTrustedIdentity(Identity)}). Once trust has been established it will also verify the issued at date
     * and the expires at date to see if these are valid. No grace period will be used.
     * @return True if the identity is trusted.
     * @throws DimeDateException If the issued at date is in the future, or if the expires at date is in the past.
     */
    public boolean isTrusted() throws DimeDateException {
        if (this.isSelfIssued()) { return false; }
        Identity trustedIdentity = Dime.getTrustedIdentity();
        if (trustedIdentity == null) { return false; }
        return isTrusted(trustedIdentity);
    }

    /**
     * Will verify if an identity can be trusted using the provided identity. Once trust has been established it will
     * also verify the issued at date and the expires at date to see if these are valid.
     * @param trustedIdentity The identity to verify the trust against.
     * @return True if the identity is trusted, false otherwise.
     * @throws DimeDateException If the issued at date is in the future, or if the expires at date is in the past.
     */
    public boolean isTrusted(Identity trustedIdentity) throws DimeDateException {
        if (trustedIdentity == null) { throw new IllegalArgumentException("Unable to verify trust, provided trusted identity must not be null."); }
        if (verifyChain(trustedIdentity) == null) {
            return false;
        }
        verifyDates(); // Verify IssuedAt and ExpiresAt
        return true;
    }


    /**
     * Will check if a particular capability has been given to an identity.
     * @param capability The capability to check for.
     * @return true or false.
     */
    public boolean hasCapability(Capability capability) {
        return getCapabilities().contains(capability);
    }

    /**
     * Will check if an identity is within a particular ambit.
     * @param ambit The ambit to check for.
     * @return true or false.
     */
    public boolean hasAmbit(String ambit) {
        List<String> ambitList = getAmbits();
        if (ambitList != null) {
            return ambitList.contains(ambit);
        }
        return false;
    }

    @Override
    public void convertToLegacy() {
        if (isLegacy()) { return; }
        super.convertToLegacy();
        Key.convertKeyToLegacy(this, Key.Use.SIGN, Claim.PUB);
    }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Di:ME envelopes.
     */
    Identity() { }

    Identity(String systemName, UUID subjectId, Key subjectKey, Instant issuedAt, Instant expiresAt, UUID issuerId, List<String> capabilities, Map<String, Object> principles, List<String> ambits, List<String> methods) {
        if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
        ClaimsMap claims = getClaims();
        claims.put(Claim.UID, UUID.randomUUID());
        claims.put(Claim.SYS, systemName);
        claims.put(Claim.SUB, subjectId);
        claims.put(Claim.ISS, issuerId);
        claims.put(Claim.IAT, issuedAt);
        claims.put(Claim.EXP, expiresAt);
        claims.put(Claim.PUB, subjectKey.getPublic());
        claims.put(Claim.CAP, capabilities);
        claims.put(Claim.PRI, principles);
        claims.put(Claim.AMB, ambits);
        claims.put(Claim.MTD, methods);
    }

    void setTrustChain(Identity trustChain) {
        this.trustChain = trustChain;
    }

    /// PROTECTED ///

    @Override
    protected void customDecoding(List<String> components) throws DimeFormatException {
        if (components.size() > Identity.MAXIMUM_NBR_COMPONENTS) { throw new DimeFormatException("More components in item than expected, got " + components.size() + ", expected maximum " + Identity.MAXIMUM_NBR_COMPONENTS); }
        if (components.size() == Identity.MAXIMUM_NBR_COMPONENTS) { // There is also a trust chain identity
            byte[] issuer = Utility.fromBase64(components.get(Identity.COMPONENTS_CHAIN_INDEX));
            this.trustChain = Identity.fromEncodedIdentity(new String(issuer, StandardCharsets.UTF_8));
        }
        this.isSigned = true; // Identities are always signed
    }

    @Override
    protected void customEncoding(StringBuilder builder) throws DimeFormatException {
        super.customEncoding(builder);
        if (this.trustChain != null) {
            builder.append(Dime.COMPONENT_DELIMITER);
            builder.append(Utility.toBase64(this.trustChain.forExport()));
        }
    }

    @Override
    protected int getMinNbrOfComponents() {
        return Identity.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final int MINIMUM_NBR_COMPONENTS = 3;
    private static final int MAXIMUM_NBR_COMPONENTS = MINIMUM_NBR_COMPONENTS + 1;
    private static final int COMPONENTS_CHAIN_INDEX = 2;
    private Identity trustChain;

    private static Identity fromEncodedIdentity(String encoded) throws DimeFormatException {
        Identity identity = new Identity();
        identity.decode(encoded);
        return identity;
    }

    private Identity verifyChain(Identity trustedIdentity) throws DimeDateException {
        Identity verifyingIdentity;
        if (trustChain != null && trustChain.getSubjectId().compareTo(trustedIdentity.getSubjectId()) != 0) {
            verifyingIdentity = trustChain.verifyChain(trustedIdentity);
        } else {
            verifyingIdentity = trustedIdentity;
        }
        if (verifyingIdentity == null) { return null; }
        try {
            super.verify(verifyingIdentity.getPublicKey());
            return this;
        } catch (DimeIntegrityException | DimeCryptographicException e) {
            return null;
        }
    }

}
