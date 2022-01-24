//
//  IdentityIssuingRequest.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Capability;
import io.dimeformat.enums.KeyType;
import io.dimeformat.exceptions.*;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * Class used to create a request for the issuing of an identity to an entity. This will contain a locally generated
 * public key (where the private key remains locally), capabilities requested and principles claimed. An issuing entity
 * uses the Identity Issuing Request (IIR) to validate and then issue a new identity for the entity.
 */
public class IdentityIssuingRequest extends Item {

    /// PUBLIC ///

    /** A constant holding the number of seconds for a year (based on 365 days). */
    public static final long VALID_FOR_1_YEAR = 365L * 24 * 60 * 60;

    /** A tag identifying the Di:ME item type, part of the header. */
    public static final String TAG = "IIR";

    /**
     * Returns the tag of the Di:ME item.
     * @return The tag of the item.
     */
    @Override
    public String getTag() {
        return IdentityIssuingRequest.TAG;
    }

    /**
     * Returns a unique identifier for the instance. This will be generated at instance creation.
     * @return A unique identifier, as a UUID.
     */
    @Override
    public UUID getUniqueId() {
        return this.claims.uid;
    }

    /**
     * The date and time when this IIR was created.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return this.claims.iat;
    }

    /**
     * Returns the public key attached to the IIR. This is the public key attached by the entity and will get included in any
     * issued identity. The equivalent secret (private) key was used to sign the IIR, thus the public key can be used
     * to verify the signature. This must be a key of type IDENTITY.
     * @return A Key instance with a public key of type IDENTITY.
     */
    public Key getPublicKey() {
        if (this.claims.pub != null && this.claims.pub.length() > 0) {
            try {
                return Key.fromBase58Key(this.claims.pub);
            } catch (DimeFormatException ignored) { /* ignored */ }
        }
        return null;
    }

    /**
     * Returns a list of any capabilities requested by this IIR. Capabilities are usually used to
     * determine what an entity may do with its issued identity.
     * @return An immutable list of Capability instances.
     */
    public List<Capability> getCapabilities() {
        return (this.claims.cap != null) ? Collections.unmodifiableList(this.claims.cap) : null;
    }

    /**
     * Returns all principles provided in the IIR. These are key-value fields that further provide information about
     * the entity. Using principles are optional.
     * @return An immutable map of assigned principles (as <String, Object>).
     */
    public Map<String, Object> getPrinciples() {
        return (this.claims.pri != null) ? Collections.unmodifiableMap(this.claims.pri) : null;
    }

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
        if (key.getKeyType() != KeyType.IDENTITY) { throw new IllegalArgumentException("Key of invalid type."); }
        if (key.getSecret() == null) { throw new IllegalArgumentException("Private key must not be null"); }
        if (key.getPublic() == null) { throw new IllegalArgumentException("Public key must not be null"); }
        IdentityIssuingRequest iir = new IdentityIssuingRequest();
        if (capabilities == null || capabilities.length == 0) {
            capabilities = new Capability[] { Capability.GENERIC };
        }
        iir.claims = new IdentityIssuingRequestClaims(UUID.randomUUID(),
                Instant.now(),
                key.getPublic(),
                capabilities,
                principles);
        iir.signature = Crypto.generateSignature(iir.encode(), key);
        return iir;
    }

    /**
     * Verifies that the IIR has been signed by the secret (private) key that is associated with the public key included
     * in the IIR. If this passes then it can be assumed that the sender is in possession of the private key used to
     * create the IIR and will also after issuing of an identity form the proof-of-ownership.
     * @return Returns the IdentityIssuingRequest instance for convenience.
     * @throws DimeDateException If the IIR was issued in the future (according to the issued at date).
     * @throws DimeIntegrityException If the signature can not be verified.
     * @throws DimeFormatException If the format of the public key inside the IIR is invalid.
     */
    public IdentityIssuingRequest verify() throws DimeDateException, DimeIntegrityException, DimeFormatException {
        verify(Key.fromBase58Key(this.claims.pub));
        return this;
    }

    /**
     * Verifies that the IIR has been signed by a secret (private) key that is associated with the provided public key.
     * If this passes then it can be assumed that the sender is in possession of the private key associated with the
     * public key used to verify. This method may be used when verifying that an IIR has been signed by the same secret
     * key that belongs to an already issued identity, this could be useful when re-issuing an identity.
     * @param key The key that should be used to verify the IIR, must be of type IDENTITY.
     * @throws DimeDateException If the IIR was issued in the future (according to the issued at date).
     * @throws DimeIntegrityException If the signature can not be verified.
     */
    @Override
    public void verify(Key key) throws DimeDateException, DimeIntegrityException {
        if (Instant.now().compareTo(this.getIssuedAt()) < 0) { throw new DimeDateException("An identity issuing request cannot have an issued at date in the future."); }
        super.verify(key);
    }

    /**
     * Checks if the IIR includes a request for a particular capability.
     * @param capability The capability to check for.
     * @return true or false.
     */
    public boolean wantsCapability(Capability capability) {
        return this.claims.cap.contains(capability);
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
     * @param allowedCapabilities A list of capabilities that must be present in the IIR to allow issuing.
     * @param requiredCapabilities A list of capabilities that will be added (if not present in the IIR) before issuing.
     * @return An Identity instance that may be sent back to the entity that proved the IIR.
     * @throws DimeDateException If the issuing identity has expired (or has an issued at date in the future).
     * @throws DimeCapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws DimeUntrustedIdentityException If the issuing identity can not be trusted.
     * @throws DimeIntegrityException If the signature of the IIR could not be verified.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException {
        return issueIdentity(subjectId, validFor, issuerKey, issuerIdentity, allowedCapabilities, requiredCapabilities, null, null);
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
     * @param allowedCapabilities A list of capabilities that must be present in the IIR to allow issuing.
     * @param requiredCapabilities A list of capabilities that will be added (if not present in the IIR) before issuing.
     * @param ambits A list of ambits that will apply to the issued identity.
     * @return An Identity instance that may be sent back to the entity that proved the IIR.
     * @throws DimeDateException If the issuing identity has expired (or has an issued at date in the future).
     * @throws DimeCapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws DimeUntrustedIdentityException If the issuing identity can not be trusted.
     * @throws DimeIntegrityException If the signature of the IIR could not be verified.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambits) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException {
        return issueIdentity(subjectId, validFor, issuerKey, issuerIdentity, allowedCapabilities, requiredCapabilities, ambits, null);
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
     * @param allowedCapabilities A list of capabilities that must be present in the IIR to allow issuing.
     * @param requiredCapabilities A list of capabilities that will be added (if not present in the IIR) before issuing.
     * @param ambits A list of ambits that will apply to the issued identity.
     * @param methods A list of methods that will apply to the issued identity.
     * @return An Identity instance that may be sent back to the entity that proved the IIR.
     * @throws DimeDateException If the issuing identity has expired (or has an issued at date in the future).
     * @throws DimeCapabilityException If the IIR contains any capabilities that are not allowed.
     * @throws DimeUntrustedIdentityException If the issuing identity can not be trusted.
     * @throws DimeIntegrityException If the signature of the IIR could not be verified.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambits, String[] methods) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException {
        if (issuerIdentity == null) { throw new IllegalArgumentException("Issuer identity must not be null."); }
        return issueNewIdentity(issuerIdentity.getSystemName(), subjectId, validFor, issuerKey, issuerIdentity, allowedCapabilities, requiredCapabilities, ambits, methods);
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
     * @param ambits A list of ambits that will apply to the issued identity.
     * @return A self-issued Identity instance.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName, String[] ambits) throws DimeCryptographicException {
        return selfIssueIdentity(subjectId, validFor, issuerKey, systemName, ambits, null);
    }

    /**
     * Will issue a new Identity instance from the IIR. The issued identity will be self-issued as it will be signed by
     * the same key that also created the IIR. This is normally used when creating a root identity for a trust chain.
     * @param subjectId The subject identifier of the entity. For a new identity this may be anything, for a re-issue it
     *                  should be the same as subject identifier used previously.
     * @param validFor The number of seconds that the identity should be valid for, from the time of issuing.
     * @param issuerKey The Key of the issuing entity, must contain a secret key of type IDENTIFY.
     * @param systemName The name of the system, or network, that the identity should be a part of.
     * @param ambits A list of ambits that will apply to the issued identity.
     * @param methods Al list of methods that will apply to the issued identity.
     * @return A self-issued Identity instance.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName, String[] ambits, String[] methods) throws DimeCryptographicException {
        try {
            if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
            return issueNewIdentity(systemName, subjectId, validFor, issuerKey, null, null, null, ambits, methods);
        } catch (DimeDateException | DimeCapabilityException | DimeUntrustedIdentityException | DimeIntegrityException e) {
            return null; // These exceptions will not be thrown when issuing a self-issued identity.
        }

    }

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope.COMPONENT_DELIMITER);
        if (components.length != IdentityIssuingRequest.NBR_COMPONENTS_WITHOUT_SIGNATURE && components.length != IdentityIssuingRequest.NBR_COMPONENTS_WITH_SIGNATURE) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected " + IdentityIssuingRequest.NBR_COMPONENTS_WITHOUT_SIGNATURE + " or  " + IdentityIssuingRequest.NBR_COMPONENTS_WITH_SIGNATURE + ", got " + components.length + "."); }
        if (components[IdentityIssuingRequest.TAG_INDEX].compareTo(IdentityIssuingRequest.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + IdentityIssuingRequest.TAG + ", got " + components[IdentityIssuingRequest.TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[IdentityIssuingRequest.CLAIMS_INDEX]);
        this.claims = new IdentityIssuingRequestClaims(new String(json, StandardCharsets.UTF_8));
        if (components.length == NBR_COMPONENTS_WITH_SIGNATURE) {
            this.encoded = encoded.substring(0, encoded.lastIndexOf(Envelope.COMPONENT_DELIMITER));
            this.signature = components[IdentityIssuingRequest.SIGNATURE_INDEX];
        }
    }

    @Override
    protected String encode() {
        if (this.encoded == null) {
            this.encoded = IdentityIssuingRequest.TAG +
                    Envelope.COMPONENT_DELIMITER +
                    Utility.toBase64(this.claims.toJSONString());
        }
        return this.encoded;
    }

    /// PRIVATE ///

    private static class IdentityIssuingRequestClaims {

        private final UUID uid;
        private final Instant iat;
        private final String pub;
        private List<Capability> cap;
        private final Map<String, Object> pri;

        public IdentityIssuingRequestClaims(UUID uid, Instant iat, String pub, Capability[] cap, Map<String, Object> pri) {
            this.uid = uid;
            this.iat = iat;
            this.pub = pub;
            this.cap = (cap != null) ? Arrays.asList(cap) : null;
            this.pri = pri;
        }

        public IdentityIssuingRequestClaims(String json) {
            JSONObject jsonObject = new JSONObject(json);
            this.uid = jsonObject.has("uid") ? UUID.fromString(jsonObject.getString("uid")) : null;
            this.iat = jsonObject.has("iat") ? Instant.parse(jsonObject.getString("iat")) : null;
            this.pub = jsonObject.has("pub") ? jsonObject.getString("pub"): null;
            if (jsonObject.has("cap")) {
                this.cap = new ArrayList<>();
                JSONArray array = jsonObject.getJSONArray("cap");
                for (int i = 0;  i < array.length(); i++) {
                    this.cap.add(Capability.valueOf(((String)array.get(i)).toUpperCase()));
                }
            } else {
                this.cap = null;
            }
            this.pri = jsonObject.has("pri") ? jsonObject.getJSONObject("pri").toMap() : null;
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            if (this.uid != null) { jsonObject.put("uid", this.uid.toString()); }
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.pub != null) { jsonObject.put("pub", this.pub); }
            if (this.cap != null) {
                String[] caps = new String[this.cap.size()];
                for (int i = 0; i < this.cap.size(); i++) {
                    caps[i] = this.cap.get(i).name().toLowerCase();
                }
                jsonObject.put("cap", caps);
            }
            if (this.pri != null) { jsonObject.put("pri", this.pri); }
            return jsonObject.toString();
        }

    }

    private static final int NBR_COMPONENTS_WITHOUT_SIGNATURE = 2;
    private static final int NBR_COMPONENTS_WITH_SIGNATURE = 3;
    private static final int TAG_INDEX = 0;
    private static final int CLAIMS_INDEX = 1;
    private static final int SIGNATURE_INDEX = 2;

    private IdentityIssuingRequestClaims claims;

    private Identity issueNewIdentity(String systemName, UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambits, String[] method) throws DimeCapabilityException, DimeUntrustedIdentityException, DimeCryptographicException, DimeIntegrityException, DimeDateException {
        verify(this.getPublicKey());
        boolean isSelfSign = (issuerIdentity == null || this.getPublicKey().getPublic().equals(issuerKey.getPublic()));
        this.completeCapabilities(allowedCapabilities, requiredCapabilities, isSelfSign);
        if (isSelfSign || issuerIdentity.hasCapability(Capability.ISSUE))
        {
            Instant now = Instant.now();
            Instant expires = now.plusSeconds(validFor);
            UUID issuerId = issuerIdentity != null ? issuerIdentity.getSubjectId() : subjectId;
            List<String> ambitList = (ambits != null) ? Arrays.asList(ambits) : null;
            List<String> methodList = (method != null) ? Arrays.asList(method) : null;
            Identity identity = new Identity(systemName, subjectId, this.getPublicKey(), now, expires, issuerId, getCapabilities(), getPrinciples(), ambitList, methodList);
            if (Identity.getTrustedIdentity() != null && issuerIdentity != null && issuerIdentity.getSubjectId() != Identity.getTrustedIdentity().getSubjectId()) {
                issuerIdentity.verifyTrust();
                // The chain will only be set if this is not the trusted identity (and as long as one is set)
                identity.setTrustChain(issuerIdentity);
            }
            identity.sign(issuerKey);
            return identity;
        }
        throw new DimeCapabilityException("Issuing identity missing 'issue' capability.");
    }

    private void completeCapabilities(Capability[] allowedCapabilities, Capability[] requiredCapabilities, boolean isSelfIssue) throws DimeCapabilityException {
        if (this.claims.cap == null) {
            this.claims.cap = new ArrayList<>();
        }
        if (isSelfIssue) {
            if (!this.wantsCapability(Capability.SELF)) {
                this.claims.cap = new ArrayList<>(this.claims.cap);
                this.claims.cap.add(Capability.SELF);
            }
        } else {
            if ((allowedCapabilities == null || allowedCapabilities.length == 0) && (requiredCapabilities == null || requiredCapabilities.length == 0)) {
                throw new IllegalArgumentException("Allowed capabilities and/or required capabilities must be defined to issue identity.");
            }
            // First check include any missing required capabilities to the iir
            if (requiredCapabilities != null && requiredCapabilities.length > 0) {
                List<Capability> tempRequiredCapabilities = new ArrayList<>(Arrays.asList(requiredCapabilities));
                tempRequiredCapabilities.removeAll(this.claims.cap);
                if (!tempRequiredCapabilities.isEmpty()) {
                    this.claims.cap = new ArrayList<>(this.claims.cap);
                    this.claims.cap.addAll(tempRequiredCapabilities);
                }
            }
            // Then check so there are no capabilities included that are not allowed
            if (allowedCapabilities != null && allowedCapabilities.length > 0) {
                List<Capability> tempCap = new ArrayList<>(this.claims.cap);
                tempCap.removeAll(Arrays.asList(allowedCapabilities));
                if (!tempCap.isEmpty()) { throw new DimeCapabilityException("Identity issuing request contains one or more disallowed capabilities."); }
            }
        }
    }

}
