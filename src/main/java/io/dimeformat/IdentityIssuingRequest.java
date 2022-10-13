//
//  IdentityIssuingRequest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.KeyCapability;
import io.dimeformat.enums.IdentityCapability;
import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.*;
import io.dimeformat.keyring.IntegrityState;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import static java.util.stream.Collectors.toList;

/**
 * Class used to create a request for the issuing of an identity to an entity. This will contain a locally generated
 * public key (where the private key remains locally), capabilities requested and principles claimed. An issuing entity
 * uses the Identity Issuing Request (IIR) to validate and then issue a new identity for the entity.
 */
public class IdentityIssuingRequest extends Item {

    /// PUBLIC ///

    /**
     * A constant holding the number of seconds for a year (based on 365 days).
     * @deprecated Will be removed in the future, use {#{@link Dime#VALID_FOR_1_YEAR}} instead.
     * */
    @Deprecated
    public static final long VALID_FOR_1_YEAR = 365L * 24 * 60 * 60;

    /** The item type identifier for Di:ME Identity Issuing Request items. */
    public static final String ITEM_IDENTIFIER = "IIR";

    @Override
    public String getItemIdentifier() {
        return IdentityIssuingRequest.ITEM_IDENTIFIER;
    }

    /**
     * Returns the public key attached to the IIR. This is the public key attached by the entity and will get included in any
     * issued identity. The equivalent secret (private) key was used to sign the IIR, thus the public key can be used
     * to verify the signature. This must be a key of type IDENTITY.
     * @return A Key instance with a public key of type IDENTITY.
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
     * Returns a list of any capabilities requested by this IIR. Capabilities are usually used to
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
     * Returns all principles provided in the IIR. These are key-value fields that further provide information about
     * the entity. Using principles are optional.
     * @return An immutable map of assigned principles.
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
     * This will generate a new IIR from a Key instance. The Key instance must be of type IDENTITY.
     * @param key The Key instance to use.
     * @return An IIR that can be used to issue a new identity (or sent to a trusted entity for issuing).
     * @throws CryptographyException If something goes wrong.
     */
    public static IdentityIssuingRequest generateIIR(Key key) throws CryptographyException {
        return generateIIR(key, null, null);
    }

    /**
     * This will generate a new IIR from a Key instance and a list of wished for capabilities. The Key instance must be
     * of type IDENTITY.
     * @param key The Key instance to use.
     * @param capabilities A list of capabilities that should be requested.
     * @return An IIR that can be used to issue a new identity (or sent to a trusted entity for issuing).
     * @throws CryptographyException If something goes wrong.
     */
    public static IdentityIssuingRequest generateIIR(Key key, IdentityCapability[] capabilities) throws CryptographyException {
        return generateIIR(key, capabilities, null);
    }

    /**
     * This will generate a new IIR from a Key instance together with a list of wished for capabilities and principles
     * to include in any issued identity. The Key instance must be of type IDENTITY.
     * @param key The Key instance to use.
     * @param capabilities A list of capabilities that should be requested.
     * @param principles A map of key-value fields that should be included in an issued identity.
     * @return An IIR that can be used to issue a new identity (or sent to a trusted entity for issuing).
     * @throws CryptographyException If something goes wrong.
     */
    public static IdentityIssuingRequest generateIIR(Key key, IdentityCapability[] capabilities, Map<String, Object> principles) throws CryptographyException {
        if (!key.getCapability().contains(KeyCapability.SIGN)) { throw new IllegalArgumentException("Key must have SIGN capability set."); }
        if (key.getSecret() == null) { throw new IllegalArgumentException("Private key must not be null"); }
        if (key.getPublic() == null) { throw new IllegalArgumentException("Public key must not be null"); }
        IdentityIssuingRequest iir = new IdentityIssuingRequest();
        iir.setClaimValue(Claim.UID, UUID.randomUUID());
        iir.setClaimValue(Claim.IAT, Utility.createTimestamp());
        iir.setClaimValue(Claim.PUB, key.getPublic());
        if (capabilities == null || capabilities.length == 0) {
            capabilities = new IdentityCapability[] { IdentityCapability.GENERIC };
        }
        List<IdentityCapability> caps = List.of(capabilities);
        iir.setClaimValue(Claim.CAP, caps.stream().map(IdentityCapability::toString).collect(Collectors.toList()));
        if (principles != null && !principles.isEmpty()) {
            iir.setClaimValue(Claim.PRI, principles);
        }
        if (key.isLegacy()) {
            iir.markAsLegacy();
        }
        iir.sign(key);
        return iir;
    }

    @Override
    public IntegrityState verify() {
        return super.verify(getPublicKey(), null);
    }

    @Override
    public IntegrityState verify(List<Item> linkedItems) {
        return super.verify(getPublicKey(), linkedItems);
    }

    /**
     * Checks if the IIR includes a request for a particular capability.
     * @param capability The capability to check for.
     * @return true or false.
     */
    public boolean wantsCapability(IdentityCapability capability) {
        return getCapabilities().contains(capability);
    }

    /**
     * Will issue a new Identity instance from the IIR. This method should only be called after the IIR has been
     * validated to meet context and application specific requirements. The only exception is the capabilities, that may
     * be validated during the issuing, by providing allowed and required capabilities. The system name of the issued
     * identity will be set to the same as the issuing identity.
     * @param subjectId The subject identifier of the entity. For a new identity this may be anything, for a re-issue it
     *                  should be the same as subject identifier used previously.
     * @param validFor The number of seconds that the identity should be valid for, from the time of issuing.
     * @param issuerKey The Key of the issuing entity, must contain a secret key of type IDENTIFY.
     * @param issuerIdentity The Identity instance of the issuing entity. If part of a trust chain, then this will be
     *                       attached to the newly issued Identity.
     * @param includeChain If set to true then the trust chain will be added to the newly issued identity. The chain
     *                     will only the included if the issuing identity is not the root node.
     * @param allowedCapabilities A list of capabilities that may be present in the IIR to allow issuing.
     * @param requiredCapabilities A list of capabilities that will be added (if not present in the IIR) before issuing.
     * @return An Identity instance that may be sent back to the entity that proved the IIR.
     * @throws CapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws IntegrityStateException If verification fails.
     * @throws CryptographyException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, IdentityCapability[] allowedCapabilities, IdentityCapability[] requiredCapabilities) throws CapabilityException, CryptographyException, IntegrityStateException {
        return issueIdentity(subjectId, validFor, issuerKey, issuerIdentity, includeChain, allowedCapabilities, requiredCapabilities, null, null);
    }

    /**
     * Will issue a new Identity instance from the IIR. This method should only be called after the IIR has been
     * validated to meet context and application specific requirements. The only exception is the capabilities, that may
     * be validated during the issuing, by providing allowed and required capabilities. If system is omitted, then the
     * issued identity will be set to the system same as the issuing identity.
     * @param subjectId The subject identifier of the entity. For a new identity this may be anything, for a re-issue it
     *                  should be the same as subject identifier used previously.
     * @param validFor The number of seconds that the identity should be valid for, from the time of issuing.
     * @param issuerKey The Key of the issuing entity, must contain a secret key of type IDENTIFY.
     * @param issuerIdentity The Identity instance of the issuing entity. If part of a trust chain, then this will be
     *                       attached to the newly issued Identity.
     * @param includeChain If set to true then the trust chain will be added to the newly issued identity. The chain
     *                     will only the included if the issuing identity is not the root node.
     * @param allowedCapabilities A list of capabilities that must be present in the IIR to allow issuing.
     * @param requiredCapabilities A list of capabilities that will be added (if not present in the IIR) before issuing.
     * @param systemName The name of the system, or network, that the identity should be a part of.
     * @param ambit An ambit list that will apply to the issued identity.
     * @return An Identity instance that may be sent back to the entity that proved the IIR.
     * @throws CapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws IntegrityStateException If verification fails.
     * @throws CryptographyException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, IdentityCapability[] allowedCapabilities, IdentityCapability[] requiredCapabilities, String systemName, String[] ambit) throws CapabilityException, CryptographyException, IntegrityStateException {
        return issueIdentity(subjectId, validFor, issuerKey, issuerIdentity, includeChain, allowedCapabilities, requiredCapabilities, systemName, ambit, null);
    }
    /**
     * Will issue a new Identity instance from the IIR. This method should only be called after the IIR has been
     * validated to meet context and application specific requirements. The only exception is the capabilities, that may
     * be validated during the issuing, by providing allowed and required capabilities. If system is omitted, then the
     * issued identity will be set to the system same as the issuing identity.
     * @param subjectId The subject identifier of the entity. For a new identity this may be anything, for a re-issue it
     *                  should be the same as subject identifier used previously.
     * @param validFor The number of seconds that the identity should be valid for, from the time of issuing.
     * @param issuerKey The Key of the issuing entity, must contain a secret key of type IDENTIFY.
     * @param issuerIdentity The Identity instance of the issuing entity. If part of a trust chain, then this will be
     *                       attached to the newly issued Identity.
     * @param includeChain If set to true then the trust chain will be added to the newly issued identity. The chain
     *                     will only the included if the issuing identity is not the root node.
     * @param allowedCapabilities A list of capabilities that must be present in the IIR to allow issuing.
     * @param requiredCapabilities A list of capabilities that will be added (if not present in the IIR) before issuing.
     * @param systemName The name of the system, or network, that the identity should be a part of.
     * @param ambit An ambit list that will apply to the issued identity.
     * @param methods A list of methods that will apply to the issued identity.
     * @return An Identity instance that may be sent back to the entity that proved the IIR.
     * @throws CapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws IntegrityStateException If verification fails.
     * @throws CryptographyException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, IdentityCapability[] allowedCapabilities, IdentityCapability[] requiredCapabilities, String systemName, String[] ambit, String[] methods) throws CapabilityException, CryptographyException, IntegrityStateException {
        if (issuerIdentity == null) { throw new IllegalArgumentException("Issuer identity must not be null."); }
        String sys = (systemName != null && systemName.length() > 0) ? systemName : issuerIdentity.getClaim(Claim.SYS);
        return issueNewIdentity(sys, subjectId, validFor, issuerKey, issuerIdentity, includeChain, allowedCapabilities, requiredCapabilities, ambit, methods);
    }

    /**
     * Will issue a new Identity instance from the IIR. The issued identity will be self-issued as it will be signed by
     * the same key that also created the IIR. This is normally used when creating a root identity for a trust chain.
     * @param subjectId The subject identifier of the entity. For a new identity this may be anything, for a re-issue it
     *                  should be the same as subject identifier used previously.
     * @param validFor The number of seconds that the identity should be valid for, from the time of issuing.
     * @param issuerKey The Key of the issuing entity, must contain a secret key of type IDENTIFY.
     * @param systemName The name of the system, or network, that the identity should be a part of.
     * @return A self-issued Identity instance.
     * @throws CryptographyException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName) throws CryptographyException {
        return selfIssueIdentity(subjectId, validFor, issuerKey, systemName, null, null);
    }

    /**
     * Will issue a new Identity instance from the IIR. The issued identity will be self-issued as it will be signed by
     * the same key that also created the IIR. This is normally used when creating a root identity for a trust chain.
     * @param subjectId The subject identifier of the entity. For a new identity this may be anything, for a re-issue it
     *                  should be the same as subject identifier used previously.
     * @param validFor The number of seconds that the identity should be valid for, from the time of issuing.
     * @param issuerKey The Key of the issuing entity, must contain a secret key of type IDENTIFY.
     * @param systemName The name of the system, or network, that the identity should be a part of.
     * @param ambit An ambit list that will apply to the issued identity.
     * @return A self-issued Identity instance.
     * @throws CryptographyException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName, String[] ambit) throws CryptographyException {
        return selfIssueIdentity(subjectId, validFor, issuerKey, systemName, ambit, null);
    }

    /**
     * Will issue a new Identity instance from the IIR. The issued identity will be self-issued as it will be signed by
     * the same key that also created the IIR. This is normally used when creating a root identity for a trust chain.
     * @param subjectId The subject identifier of the entity. For a new identity this may be anything, for a re-issue it
     *                  should be the same as subject identifier used previously.
     * @param validFor The number of seconds that the identity should be valid for, from the time of issuing.
     * @param issuerKey The Key of the issuing entity, must contain a secret key of type IDENTIFY.
     * @param systemName The name of the system, or network, that the identity should be a part of.
     * @param ambit An ambit list that will apply to the issued identity.
     * @param methods A list of methods that will apply to the issued identity.
     * @return A self-issued Identity instance.
     * @throws CryptographyException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName, String[] ambit, String[] methods) throws CryptographyException {
        try {
            if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
            return issueNewIdentity(systemName, subjectId, validFor, issuerKey, null, false, null, null, ambit, methods);
        } catch (CapabilityException | IntegrityStateException e) {
            return null; // These exceptions will not be thrown when issuing a self-issued identity.
        }

    }

    @Override
    public void convertToLegacy() {
        if (isLegacy()) { return; }
        super.convertToLegacy();
        Key.convertKeyToLegacy(this, KeyCapability.SIGN, Claim.PUB);
    }

    /// PROTECTED ///

    @Override
    protected boolean allowedToSetClaimDirectly(Claim claim) {
        return IdentityIssuingRequest.allowedClaims.contains(claim);
    }

    @Override
    protected void customDecoding(List<String> components) {
        this.isSigned = true; // Identity issuing requests are always signed
    }

    @Override
    protected int getMinNbrOfComponents() {
        return IdentityIssuingRequest.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.KID, Claim.MTD, Claim.PRI, Claim.SUB, Claim.SYS, Claim.UID);
    private static final int MINIMUM_NBR_COMPONENTS = 3;

    private Identity issueNewIdentity(String systemName, UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, IdentityCapability[] allowedCapabilities, IdentityCapability[] requiredCapabilities, String[] ambit, String[] methods) throws IntegrityStateException, CapabilityException, CryptographyException {
        IntegrityState state = verify(this.getPublicKey());
        if (!state.isValid()) {
            throw new IntegrityStateException(state, "Unable to verify IIR.");
        }
        boolean isSelfSign = (issuerIdentity == null || this.getPublicKey().getPublic().equals(issuerKey.getPublic()));
        strip();
        this.completeCapabilities(allowedCapabilities, requiredCapabilities, isSelfSign);
        if (isSelfSign || issuerIdentity.hasCapability(IdentityCapability.ISSUE))
        {
            Instant now = Utility.createTimestamp();
            Instant expires = now.plusSeconds(validFor);
            UUID issuerId = issuerIdentity != null ? issuerIdentity.getClaim(Claim.SUB) : subjectId;
            List<String> ambitList = ambit != null ? List.of(ambit) : null;
            List<String> methodList = methods != null ? List.of(methods) : null;
            Identity identity = new Identity(systemName,
                    subjectId,
                    this.getPublicKey(),
                    now, expires,
                    issuerId,
                    getClaim(Claim.CAP),
                    getPrinciples(),
                    ambitList,
                    methodList);
            if (issuerIdentity != null ) {
                if (Dime.keyRing.get(issuerIdentity.getClaim(Claim.SUB).toString().toLowerCase()) == null && includeChain) {
                    // The chain will only be set if the issuer identity is not a trusted identity in the key ring
                    state = issuerIdentity.verify();
                    if (!state.isValid()) {
                        throw new IntegrityStateException(state, "Unable to verify issuer identity.");
                    }
                    identity.setTrustChain(issuerIdentity);
                } else {
                    state = Item.verifyDates(issuerIdentity);
                    if (!state.isValid()) {
                        throw new IntegrityStateException(state, "Unable to verify valid dates of issuer identity.");
                    }
                }
            }
            if (this.isLegacy()) {
                identity.markAsLegacy();
            }
            identity.sign(issuerKey);
            return identity;
        }
        throw new CapabilityException("Issuing identity missing ISSUE capability.");
    }

    private void completeCapabilities(IdentityCapability[] allowedCapabilities, IdentityCapability[] requiredCapabilities, boolean isSelfIssue) throws CapabilityException {
        ArrayList<IdentityCapability> capabilities;
        ArrayList<String> caps = getClaim(Claim.CAP);
        if (caps != null) {
            capabilities = (ArrayList<IdentityCapability>) caps.stream().map(IdentityCapability::fromString).collect(Collectors.toList());
        } else {
            capabilities = new ArrayList<>();
        }
        if (isSelfIssue) {
            if (!wantsCapability(IdentityCapability.SELF)) {
                capabilities.add(IdentityCapability.SELF);
            }
        } else {
            if ((allowedCapabilities == null || allowedCapabilities.length == 0) && (requiredCapabilities == null || requiredCapabilities.length == 0)) {
                throw new IllegalArgumentException("Allowed capabilities and/or required capabilities must be defined to issue identity.");
            }
            // First check include any missing required capabilities to the iir
            if (requiredCapabilities != null && requiredCapabilities.length > 0) {
                List<IdentityCapability> tempRequiredCapabilities = new ArrayList<>(Arrays.asList(requiredCapabilities));
                tempRequiredCapabilities.removeAll(capabilities);
                if (!tempRequiredCapabilities.isEmpty()) {
                    capabilities.addAll(tempRequiredCapabilities);
                }
            }
            // Then check so there are no capabilities included that are not allowed
            if (allowedCapabilities != null && allowedCapabilities.length > 0) {
                List<IdentityCapability> tempCap = new ArrayList<>(capabilities);
                tempCap.removeAll(Arrays.asList(allowedCapabilities));
                if (!tempCap.isEmpty()) {
                    throw new CapabilityException("Identity issuing request contains one or more disallowed capabilities.");
                }
            }
        }
        setClaimValue(Claim.CAP, capabilities.stream().map(cap -> cap.toString().toLowerCase()).collect(Collectors.toList()));
    }

}
