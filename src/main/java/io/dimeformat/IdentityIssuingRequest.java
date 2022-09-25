//
//  IdentityIssuingRequest.java
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
            _publicKey = getClaims().getKey(Claim.PUB, List.of(Key.Use.SIGN));
        }
        return _publicKey;
    }
    private Key _publicKey;

    /**
     * Returns a list of any capabilities requested by this IIR. Capabilities are usually used to
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
     * Returns all principles provided in the IIR. These are key-value fields that further provide information about
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
     * This will generate a new IIR from a Key instance. The Key instance must be of type IDENTITY.
     * @param key The Key instance to use.
     * @return An IIR that can be used to issue a new identity (or sent to a trusted entity for issuing).
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static IdentityIssuingRequest generateIIR(Key key) throws DimeCryptographicException {
        return generateIIR(key, null, null);
    }

    /**
     * This will generate a new IIR from a Key instance and a list of wished for capabilities. The Key instance must be
     * of type IDENTITY.
     * @param key The Key instance to use.
     * @param capabilities A list of capabilities that should be requested.
     * @return An IIR that can be used to issue a new identity (or sent to a trusted entity for issuing).
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static IdentityIssuingRequest generateIIR(Key key, Capability[] capabilities) throws DimeCryptographicException {
        return generateIIR(key, capabilities, null);
    }

    /**
     * This will generate a new IIR from a Key instance together with a list of wished for capabilities and principles
     * to include in any issued identity. The Key instance must be of type IDENTITY.
     * @param key The Key instance to use.
     * @param capabilities A list of capabilities that should be requested.
     * @param principles A map of key-value fields that should be included in an issued identity.
     * @return An IIR that can be used to issue a new identity (or sent to a trusted entity for issuing).
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static IdentityIssuingRequest generateIIR(Key key, Capability[] capabilities, Map<String, Object> principles) throws DimeCryptographicException {
        if (!key.getUse().contains(Key.Use.SIGN)) { throw new IllegalArgumentException("Key most have SIGN usage set."); }
        if (key.getSecret() == null) { throw new IllegalArgumentException("Private key must not be null"); }
        if (key.getPublic() == null) { throw new IllegalArgumentException("Public key must not be null"); }
        IdentityIssuingRequest iir = new IdentityIssuingRequest();
        iir.getClaims().put(Claim.UID, UUID.randomUUID());
        iir.getClaims().put(Claim.IAT, Utility.createTimestamp());
        iir.getClaims().put(Claim.PUB, key.getPublic());
        if (capabilities == null || capabilities.length == 0) {
            capabilities = new Capability[] { Capability.GENERIC };
        }
        List<Capability> caps = List.of(capabilities);
        iir.getClaims().put(Claim.CAP, caps.stream().map(cap -> cap.toString().toLowerCase()).collect(Collectors.toList()));
        if (principles != null && !principles.isEmpty()) {
            iir.getClaims().put(Claim.PRI, principles);
        }
        iir.sign(key);
        return iir;
    }

    /**
     * Verifies that the IIR has been signed by the secret (private) key that is associated with the public key included
     * in the IIR. If this passes then it can be assumed that the sender is in possession of the private key used to
     * create the IIR and will also after issuing of an identity form the proof-of-ownership.
     * @throws DimeDateException If the IIR was issued in the future (according to the issued at date).
     * @throws DimeIntegrityException If the signature can not be verified.
     * @throws DimeFormatException If the format of the public key inside the IIR is invalid.
     */
    public void verify() throws DimeDateException, DimeIntegrityException, DimeFormatException, DimeCryptographicException {
        super.verify(getPublicKey(), null);
    }

    /**
     * Verifies that the IIR has been signed by the secret (private) key that is associated with the public key included
     * in the IIR. If this passes then it can be assumed that the sender is in possession of the private key used to
     * create the IIR and will also after issuing of an identity form the proof-of-ownership. This will also verify any
     * items that may be linked in the IIR.
     * @param linkedItems A list of Dime items that should be verified towards any item links in the Dime item.
     * @throws DimeDateException If the IIR was issued in the future (according to the issued at date).
     * @throws DimeIntegrityException If the signature can not be verified.
     * @throws DimeFormatException If the format of the public key inside the IIR is invalid.
     */
    public void verify(List<Item> linkedItems) throws DimeDateException, DimeIntegrityException, DimeFormatException, DimeCryptographicException {
        super.verify(getPublicKey(), linkedItems);
    }

    /**
     * Checks if the IIR includes a request for a particular capability.
     * @param capability The capability to check for.
     * @return true or false.
     */
    public boolean wantsCapability(Capability capability) {
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
     * @throws DimeDateException If the issuing identity has expired (or has an issued at date in the future).
     * @throws DimeCapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws DimeUntrustedIdentityException If the issuing identity can not be trusted.
     * @throws DimeIntegrityException If the signature of the IIR could not be verified.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, Capability[] allowedCapabilities, Capability[] requiredCapabilities) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException {
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
     * @throws DimeDateException If the issuing identity has expired (or has an issued at date in the future).
     * @throws DimeCapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws DimeUntrustedIdentityException If the issuing identity can not be trusted.
     * @throws DimeIntegrityException If the signature of the IIR could not be verified.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String systemName,  String[] ambit) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException {
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
     * @throws DimeDateException If the issuing identity has expired (or has an issued at date in the future).
     * @throws DimeCapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws DimeUntrustedIdentityException If the issuing identity can not be trusted.
     * @throws DimeIntegrityException If the signature of the IIR could not be verified.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String systemName, String[] ambit, String[] methods) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException {
        if (issuerIdentity == null) { throw new IllegalArgumentException("Issuer identity must not be null."); }
        String sys = (systemName != null && systemName.length() > 0) ? systemName : issuerIdentity.getSystemName();
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
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName) throws DimeCryptographicException {
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
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName, String[] ambit) throws DimeCryptographicException {
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
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName, String[] ambit, String[] methods) throws DimeCryptographicException {
        try {
            if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
            return issueNewIdentity(systemName, subjectId, validFor, issuerKey, null, false, null, null, ambit, methods);
        } catch (DimeDateException | DimeCapabilityException | DimeUntrustedIdentityException | DimeIntegrityException e) {
            return null; // These exceptions will not be thrown when issuing a self-issued identity.
        }

    }

    @Override
    public void convertToLegacy() {
        if (isLegacy()) { return; }
        super.convertToLegacy();
        Key.convertKeyToLegacy(this, Key.Use.SIGN, Claim.PUB);
    }

    /// PROTECTED ///

    @Override
    protected void customDecoding(List<String> components) {
        this.isSigned = true; // Identity issuing requests are always signed
    }

    @Override
    protected int getMinNbrOfComponents() {
        return IdentityIssuingRequest.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final int MINIMUM_NBR_COMPONENTS = 3;

    private Identity issueNewIdentity(String systemName, UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, boolean includeChain, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambit, String[] methods) throws DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException, DimeDateException {
        verify(this.getPublicKey());
        boolean isSelfSign = (issuerIdentity == null || this.getPublicKey().getPublic().equals(issuerKey.getPublic()));
        this.completeCapabilities(allowedCapabilities, requiredCapabilities, isSelfSign);
        if (isSelfSign || issuerIdentity.hasCapability(Capability.ISSUE))
        {
            Instant now = Utility.createTimestamp();
            Instant expires = now.plusSeconds(validFor);
            UUID issuerId = issuerIdentity != null ? issuerIdentity.getSubjectId() : subjectId;
            List<String> ambitList = ambit != null ? List.of(ambit) : null;
            List<String> methodList = methods != null ? List.of(methods) : null;
            Identity identity = new Identity(systemName,
                    subjectId,
                    this.getPublicKey(),
                    now, expires,
                    issuerId,
                    getClaims().get(Claim.CAP),
                    getPrinciples(),
                    ambitList,
                    methodList);
            if (Dime.getTrustedIdentity() != null && issuerIdentity != null && issuerIdentity.getSubjectId().compareTo(Dime.getTrustedIdentity().getSubjectId()) != 0) {
                issuerIdentity.isTrusted();
                // The chain will only be set if this is not the trusted identity (and as long as one is set)
                // and if it is a trusted issuer identity (from set trusted identity) and includeChain is set to true
                if (includeChain) {
                    identity.setTrustChain(issuerIdentity);
                }
            }
            identity.sign(issuerKey);
            return identity;
        }
        throw new DimeCapabilityException("Issuing identity missing 'issue' capability.");
    }

    private void completeCapabilities(Capability[] allowedCapabilities, Capability[] requiredCapabilities, boolean isSelfIssue) throws DimeCapabilityException {
        ArrayList<Capability> capabilities;
        ArrayList<String> caps = getClaims().get(Claim.CAP);
        if (caps != null) {
            capabilities = (ArrayList<Capability>) caps.stream().map(cap -> Capability.valueOf(cap.toUpperCase())).collect(Collectors.toList());
        } else {
            capabilities = new ArrayList<>();
        }
        if (isSelfIssue) {
            if (!wantsCapability(Capability.SELF)) {
                capabilities.add(Capability.SELF);
            }
        } else {
            if ((allowedCapabilities == null || allowedCapabilities.length == 0) && (requiredCapabilities == null || requiredCapabilities.length == 0)) {
                throw new IllegalArgumentException("Allowed capabilities and/or required capabilities must be defined to issue identity.");
            }
            // First check include any missing required capabilities to the iir
            if (requiredCapabilities != null && requiredCapabilities.length > 0) {
                List<Capability> tempRequiredCapabilities = new ArrayList<>(Arrays.asList(requiredCapabilities));
                tempRequiredCapabilities.removeAll(capabilities);
                if (!tempRequiredCapabilities.isEmpty()) {
                    capabilities.addAll(tempRequiredCapabilities);
                }
            }
            // Then check so there are no capabilities included that are not allowed
            if (allowedCapabilities != null && allowedCapabilities.length > 0) {
                List<Capability> tempCap = new ArrayList<>(capabilities);
                tempCap.removeAll(Arrays.asList(allowedCapabilities));
                if (!tempCap.isEmpty()) {
                    throw new DimeCapabilityException("Identity issuing request contains one or more disallowed capabilities.");
                }
            }
        }
        getClaims().put(Claim.CAP, capabilities.stream().map(cap -> cap.toString().toLowerCase()).collect(Collectors.toList()));
    }

}
