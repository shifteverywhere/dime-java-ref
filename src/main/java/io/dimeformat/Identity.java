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
        return getClaim(Claim.SYS);
    }

    /**
     * Returns the entity's subject identifier. This is, within the system, defined by system name, unique for one
     * specific entity.
     * @return The subject identifier assigned to an entity, as a UUID.
     */
    public UUID getSubjectId() {
        return getClaim(Claim.SUB);
    }

    /**
     * Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
     * public key or type IDENTITY.
     * @return A Key instance with a public key of type IDENTITY.
     */
    public Key getPublicKey() {
        if (_publicKey == null) {
            try {
                _publicKey = new Key(List.of(KeyCapability.SIGN), getClaim(Claim.PUB), Claim.PUB);
            } catch (DimeCryptographicException e) {
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
     * @return An immutable map of assigned principles (as <String, Object>).
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
     * Returns an ambit list assigned to an identity. An ambit defines the scope, region or role where an identity
     * may be used.
     * @return An immutable ambit list (as String instances).
     */
    public List<String> getAmbitList() {
        return getClaim(Claim.AMB);
    }

    /**
     * Returns a list of methods associated with an identity. The usage of this is normally context or application
     * specific, and may specify different methods that can be used convert, transfer or further process a Di:ME
     * identity.
     * @return An immutable list of methods (as String instances).
     */
    public List<String> getMethods() {
        return getClaim(Claim.MTD);
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
        return getSubjectId().compareTo(getIssuerId()) == 0 && hasCapability(IdentityCapability.SELF);
    }

    @Override
    public void verify(List<Item> linkedItems) throws VerificationException {
        Identity trustChain = getTrustChain();
        if (trustChain != null) {
            trustChain.verify();
            Item.verifyDates(this);
            if (linkedItems != null && !linkedItems.isEmpty()) {
                verifyLinkedItems(linkedItems);
            }
            verify(trustChain.getPublicKey());
        } else {
            super.verify(linkedItems);
        }
    }

    /**
     * Will check if a particular capability has been given to an identity.
     * @param capability The capability to check for.
     * @return true or false.
     */
    public boolean hasCapability(IdentityCapability capability) {
        return getCapabilities().contains(capability);
    }

    /**
     * Will check if an identity is within a particular ambit.
     * @param ambit The ambit to check for.
     * @return true or false.
     */
    public boolean hasAmbit(String ambit) {
        List<String> ambitList = getAmbitList();
        if (ambitList != null) {
            return ambitList.contains(ambit);
        }
        return false;
    }

    @Override
    public void convertToLegacy() {
        if (isLegacy()) { return; }
        super.convertToLegacy();
        Key.convertKeyToLegacy(this, KeyCapability.SIGN, Claim.PUB);
    }

    public void sign(Identity issuer, Key key, boolean includeChain) throws DimeCryptographicException {

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

    Identity(String systemName, UUID subjectId, Key subjectKey, Instant issuedAt, Instant expiresAt, UUID issuerId, List<String> capabilities, Map<String, Object> principles, List<String> ambits, List<String> methods) {
        if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
        putClaim(Claim.UID, UUID.randomUUID());
        putClaim(Claim.SYS, systemName);
        putClaim(Claim.SUB, subjectId);
        putClaim(Claim.ISS, issuerId);
        putClaim(Claim.IAT, issuedAt);
        putClaim(Claim.EXP, expiresAt);
        putClaim(Claim.PUB, subjectKey.getPublic());
        putClaim(Claim.CAP, capabilities);
        putClaim(Claim.PRI, principles);
        putClaim(Claim.AMB, ambits);
        putClaim(Claim.MTD, methods);
    }

    void setTrustChain(Identity trustChain) {
        this.trustChain = trustChain;
    }

    /// PROTECTED ///

    @Override
    protected boolean validClaim(Claim claim) {
        return claim != Claim.MIM && claim != Claim.KEY;
    }

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

}
