//
//  Identity.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
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

    /** A tag identifying the Di:ME item type, part of the header. */
    public static final String TAG = "ID";

    /**
     * Returns the tag of the Di:ME item.
     * @return The tag of the item.
     */
    @Override
    public String getTag() {
        return Identity.TAG;
    }

    /**
     * Returns the name of the system or network that the entity belongs to. If issued by another entity and part of a
     * trust chain, then all entities will share the same system name.
     * @return The system name
     */
    public String getSystemName() {
        return claims.get(Claim.SYS);
    }

    /**
     * Returns a unique identifier for the instance. This will be assigned when issuing an identity, but will change
     * with each re-issuing even if it is for the same entity.
     * @return A unique identifier, as a UUID.
     */
    @Override
    public UUID getUniqueId() {
        return claims.getUUID(Claim.UID);
    }

    /**
     * Returns the entity's subject identifier. This is, within the system, defined by system name, unique for one
     * specific entity.
     * @return The subject identifier assigned to an entity, as a UUID.
     */
    public UUID getSubjectId() {
        return claims.getUUID(Claim.SUB);
    }

    /**
     * Returns the issuer's subject identifier. The issuer is the entity that has issued the identity to another
     * entity. If this value is equal to the subject identifier, then this identity is self-issued.
     * @return The issuer identifier, as a UUID.
     */
    public UUID getIssuerId() {
        return claims.getUUID(Claim.ISS);
    }

    /**
     * The date and time when this identity was issued. Although, this date will most often be in the past, the identity
     * should not be used and not trusted before this date.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return claims.getInstant(Claim.IAT);
    }

    /**
     * The date and time when the identity will expire, and should not be used and not trusted anymore.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getExpiresAt() {
        return claims.getInstant(Claim.EXP);
    }

    /**
     * Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
     * public key or type IDENTITY.
     * @return A Key instance with a public key of type IDENTITY.
     */
    public Key getPublicKey() {
        if (_publicKey == null) {
            String pub = claims.get(Claim.PUB);
            if (pub != null && pub.length() > 0) {
                try {
                    _publicKey = Key.fromBase58Key(pub);
                } catch (DimeFormatException ignored) { /* ignored */ }
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
    public List<Capability> getCapabilities() {
        if (_capabilities == null) {
            List<String> caps = claims.get(Claim.CAP);
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
            Map<String, Object> pri = claims.get(Claim.PRI);
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
    public List<String> getAmbits() {
        return claims.get(Claim.AMB);
    }

    /**
     * Returns a list of methods associated with an identity. The usage of this is normally context or application
     * specific, and may specify different methods that can be used convert, transfer or further process a Di:ME
     * identity.
     * @return An immutable list of methods (as String instances).
     */
    public List<String> getMethods() {
        return claims.get(Claim.MTD);
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
     */
    public static synchronized Identity getTrustedIdentity() {
        return Identity.trustedIdentity;
    }

    /**
     * Sets an Identity instance to be the trusted identity used for verifying a trust chain of other Identity
     * instances. This is normally the root identity of a trust chain.
     * @param trustedIdentity The Identity instance to set as a trusted identity.
     */
    public static synchronized void setTrustedIdentity(Identity trustedIdentity) {
        Identity.trustedIdentity = trustedIdentity;
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
     * and the expires at date to see if these are valid.
     * @return True if the identity is trusted.
     * @throws DimeDateException If the issued at date is in the future, or if the expires at date is in the past.
     */
    public boolean isTrusted() throws DimeDateException {
        if (Identity.trustedIdentity == null) { throw new IllegalStateException("Unable to verify trust, no global trusted identity set."); }
        return isTrusted(Identity.trustedIdentity);
    }

    /**
     * Will verify if an identity can be trusted by a provided identity. An identity is trusted if it exists on the same
     * branch and later in the branch as the provided identity. Once trust has been established it will also verify the
     * issued at date and the expires at date to see if these are valid.
     * @param trustedIdentity The identity to verify the trust from.
     * @return True if the identity is trusted.
     * @throws DimeDateException If the issued at date is in the future, or if the expires at date is in the past.
     */
    public boolean isTrusted(Identity trustedIdentity) throws DimeDateException {
        if (trustedIdentity == null) { throw new IllegalArgumentException("Unable to verify trust, provided trusted identity must not be null."); }
        if (verifyChain(trustedIdentity) == null) {
            return false;
        }
        Instant now = Instant.now();
        if (this.getIssuedAt().compareTo(now) > 0) { throw new DimeDateException("Identity is not yet valid, issued at date in the future."); }
        if (this.getIssuedAt().compareTo(this.getExpiresAt()) > 0) { throw new DimeDateException("Invalid expiration date, expires at before issued at."); }
        if (this.getExpiresAt().compareTo(now) < 0) { throw new DimeDateException("Identity has expired."); }
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
        List<String> ambits = getAmbits();
        if (ambits != null) {
            return ambits.contains(ambit);
        }
        return false;
    }

    /// PACKAGE-PRIVATE ///

    Identity() { }

    Identity(String systemName, UUID subjectId, Key subjectKey, Instant issuedAt, Instant expiresAt, UUID issuerId, List<String> capabilities, Map<String, Object> principles, List<String> ambits, List<String> methods) {
        if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
        this.claims = new ClaimsMap();
        this.claims.put(Claim.SYS, systemName);
        this.claims.put(Claim.SUB, subjectId);
        this.claims.put(Claim.ISS, issuerId);
        this.claims.put(Claim.IAT, issuedAt);
        this.claims.put(Claim.EXP, expiresAt);
        this.claims.put(Claim.PUB, subjectKey.getPublic());
        this.claims.put(Claim.CAP, capabilities);
        this.claims.put(Claim.PRI, principles);
        this.claims.put(Claim.AMB, ambits);
        this.claims.put(Claim.MTD, methods);
    }

    void setTrustChain(Identity trustChain) {
        this.trustChain = trustChain;
    }

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope.COMPONENT_DELIMITER);
        if (components.length != Identity.NBR_EXPECTED_COMPONENTS_MIN &&
                components.length != Identity.NBR_EXPECTED_COMPONENTS_MAX) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected "+ Identity.NBR_EXPECTED_COMPONENTS_MIN + " or " + Identity.NBR_EXPECTED_COMPONENTS_MAX +", got " + components.length + "."); }
        if (components[Identity.TAG_INDEX].compareTo(Identity.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + Identity.TAG + ", got " + components[Identity.TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Identity.CLAIMS_INDEX]);
        claims = new ClaimsMap(new String(json, StandardCharsets.UTF_8));
        if (components.length == Identity.NBR_EXPECTED_COMPONENTS_MAX) { // There is also a trust chain identity
            byte[] issIdentity = Utility.fromBase64(components[Identity.CHAIN_INDEX]);
            this.trustChain = Identity.fromEncodedIdentity(new String(issIdentity, StandardCharsets.UTF_8));
        }
        this.encoded = encoded.substring(0, encoded.lastIndexOf(Envelope.COMPONENT_DELIMITER));
        this.signature = components[components.length - 1];
    }

    @Override
    protected String encode()  {
        if (this.encoded == null) {
            StringBuilder builder = new StringBuilder();
            builder.append(Identity.TAG);
            builder.append(Envelope.COMPONENT_DELIMITER);
            builder.append(Utility.toBase64(claims.toJSON()));
            if (this.trustChain != null) {
                builder.append(Envelope.COMPONENT_DELIMITER);
                builder.append(Utility.toBase64(this.trustChain.encode() + Envelope.COMPONENT_DELIMITER + this.trustChain.signature));
            }
            this.encoded = builder.toString();
        }
        return this.encoded;
    }

    /// PRIVATE ///

    private static final int NBR_EXPECTED_COMPONENTS_MIN = 3;
    private static final int NBR_EXPECTED_COMPONENTS_MAX = 4;
    private static final int TAG_INDEX = 0;
    private static final int CLAIMS_INDEX = 1;
    private static final int CHAIN_INDEX = 2;

    private static Identity trustedIdentity;
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
        } catch (DimeIntegrityException e) {
            return null;
        }
    }

}
