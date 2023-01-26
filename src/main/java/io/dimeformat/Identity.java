//
//  Identity.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.*;
import io.dimeformat.enums.IdentityCapability;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.keyring.IntegrityState;
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

    /** The item header for DiME Identity items. */
    public static final String HEADER = "ID";

    @Override
    public String getHeader() {
        return Identity.HEADER;
    }

    /**
     * Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
     * public key with the capability 'SIGN'.
     * @return A Key instance with a public key with the capability 'SIGN'.
     */
    public Key getPublicKey() {
        if (_publicKey == null) {
            try {
                _publicKey = new Key(List.of(KeyCapability.SIGN), getClaim(Claim.PUB), Claim.PUB);
            } catch (CryptographyException e) {
                return null; // Ignored for now
            }
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
    public List<IdentityCapability> getCapabilities() {
        if (_capabilities == null) {
            List<String> caps = getClaim(Claim.CAP);
            _capabilities = caps.stream().map(IdentityCapability::fromString).collect(toList());
        }
        return _capabilities;
    }
    private List<IdentityCapability> _capabilities;

    /**
     * Returns all principles assigned to an identity. These are key-value fields that further provide information about
     * the entity. Using principles are optional.
     * @return An immutable map of assigned principles).
     */
    public Map<String, Object> getPrinciples() {
        if (_principles == null) {
            Map<String, Object> pri = getClaim(Claim.PRI);
            if (pri != null) {
                _principles = Collections.unmodifiableMap(pri);
            }
        }
        return _principles;
    }
    private Map<String, Object> _principles;

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
        return ((UUID) getClaim(Claim.SUB)).compareTo(getClaim(Claim.ISS)) == 0 && hasCapability(IdentityCapability.SELF);
    }

    /**
     * Verifies the integrity and over all validity and trust of the item. The verification will be made using the public
     * key in the provided identity. The verification will also check if the item has been issued by the provided
     * identity, if the "iss" claim has been set. If the identity has a trust chain, then this will be taken into
     * considerations while verifying.
     * @param trustedIdentity A trusted identity to verify with, may be from anywhere in the trust chain.
     * @param linkedItems A list of item where item links should be verified, may be null.
     * @return The integrity state of the verification.
     */
    @Override
    public IntegrityState verify(Identity trustedIdentity, List<Item> linkedItems) {
        IntegrityState state = IntegrityState.FAILED_NOT_TRUSTED;
        Identity trustChain = getTrustChain();
        if (trustChain != null) {
            state = super.verify(trustChain, null);
            if (state.isValid()) {
                if (!trustChain.getClaim(Claim.SUB).equals(trustedIdentity.getClaim(Claim.SUB))) {
                    state = trustChain.verify(trustedIdentity, null);
                } else {
                    if (trustedIdentity.isSelfIssued()) {
                        // If this is the end of the trust chain, then verify the final identity
                        return trustedIdentity.verify(trustedIdentity.getPublicKey());
                    } else {
                        // If this is a truncated trust chain, then verify only the dates
                        state = trustedIdentity.verifyDates();
                        return !state.isValid() ? state : IntegrityState.INTACT;
                    }
                }
            }
            if (state.isValid() && linkedItems != null) {
                state = verifyLinkedItems(linkedItems);
            }
        } else {
            state = super.verify(trustedIdentity, linkedItems);
        }
        return state;
    }

    @Override
    public IntegrityState verify(Key verifyKey, List<Item> linkedItems) {
        Identity trustChain = getTrustChain();
        if (trustChain == null || verifyKey != null) {
            return super.verify(verifyKey, linkedItems);
        }
        IntegrityState state = trustChain.verify();
        return !state.isValid() ? state : super.verify(trustChain.getPublicKey(), linkedItems);
    }

    /**
     * Will check if a particular capability has been given to an identity.
     * @param capability The capability to check for.
     * @return true or false.
     */
    public boolean hasCapability(IdentityCapability capability) {
        return getCapabilities().contains(capability);
    }

    @Override
    public void convertToLegacy() {
        if (isLegacy()) { return; }
        super.convertToLegacy();
        Key.convertKeyToLegacy(this, KeyCapability.SIGN, Claim.PUB);
    }

    public void sign(Identity issuer, Key key, boolean includeChain) throws CryptographyException {

        if (includeChain) {
            setTrustChain(issuer);
        }

        super.sign(key);

    }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Di:ME envelopes.
     */
    Identity() { }

    Identity(String systemName, UUID subjectId, Key subjectKey, Instant issuedAt, Instant expiresAt, UUID issuerId, List<String> capabilities, Map<String, Object> principles, List<String> ambitList, List<String> methods) {
        if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
        setClaimValue(Claim.UID, UUID.randomUUID());
        setClaimValue(Claim.SYS, systemName);
        setClaimValue(Claim.SUB, subjectId);
        setClaimValue(Claim.ISS, issuerId);
        setClaimValue(Claim.IAT, issuedAt);
        setClaimValue(Claim.EXP, expiresAt);
        setClaimValue(Claim.PUB, subjectKey.getPublic());
        setClaimValue(Claim.CAP, capabilities);
        setClaimValue(Claim.PRI, principles);
        setClaimValue(Claim.AMB, ambitList);
        setClaimValue(Claim.MTD, methods);
    }

    void setTrustChain(Identity trustChain) {
        this.trustChain = trustChain;
    }

    /// PROTECTED ///

    @Override
    protected boolean allowedToSetClaimDirectly(Claim claim) {
        return Identity.allowedClaims.contains(claim);
    }

    @Override
    protected void customDecoding(List<String> components) throws InvalidFormatException {
        if (components.size() > Identity.MAXIMUM_NBR_COMPONENTS) { throw new InvalidFormatException("More components in item than expected, got " + components.size() + ", expected maximum " + Identity.MAXIMUM_NBR_COMPONENTS); }
        if (components.size() == Identity.MAXIMUM_NBR_COMPONENTS) { // There is also a trust chain identity
            byte[] issuer = Utility.fromBase64(components.get(Identity.COMPONENTS_CHAIN_INDEX));
            this.trustChain = Identity.fromEncodedIdentity(new String(issuer, StandardCharsets.UTF_8));
        }
        this.isSigned = true; // Identities are always signed
    }

    @Override
    protected void customEncoding(StringBuilder builder) throws InvalidFormatException {
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

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.ISU, Claim.KID, Claim.MTD, Claim.PRI, Claim.SUB, Claim.SYS, Claim.UID);
    private static final int MINIMUM_NBR_COMPONENTS = 3;
    private static final int MAXIMUM_NBR_COMPONENTS = MINIMUM_NBR_COMPONENTS + 1;
    private static final int COMPONENTS_CHAIN_INDEX = 2;
    private Identity trustChain;

    private static Identity fromEncodedIdentity(String encoded) throws InvalidFormatException {
        Identity identity = new Identity();
        identity.decode(encoded);
        return identity;
    }

}
