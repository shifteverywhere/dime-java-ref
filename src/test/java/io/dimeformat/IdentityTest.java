//
//  IdentityIssuingRequestTest.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;
import io.dimeformat.exceptions.DimeUntrustedIdentityException;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class IdentityTest {

    @Test
    void getTagTest1() {
       Identity identity = new Identity();
       assertEquals("ID", identity.getTag());
    }

    @Test
    public void issueTest1() {
        try {
            Identity.setTrustedIdentity(null);
            UUID subjectId = UUID.randomUUID();
            Key key = Key.generateKey(KeyType.IDENTITY);            
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).selfIssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 10, key, Commons.SYSTEM_NAME, null);
            //String k = key.exportToEncoded();
            //String i = identity.exportToEncoded();
            assertEquals(Commons.SYSTEM_NAME, identity.getSystemName());
            assertTrue(subjectId == identity.getSubjectId());
            assertTrue(subjectId == identity.getIssuerId());
            assertTrue(identity.hasCapability(caps[0]));
            assertTrue(identity.hasCapability(caps[1]));
            assertTrue(identity.hasCapability(Capability.SELF));
            assertEquals(key.getPublic(), identity.getPublicKey());
            assertNotNull(identity.getIssuedAt());
            assertNotNull(identity.getExpiresAt());
            assertTrue(identity.getIssuedAt().compareTo(identity.getExpiresAt()) < 0);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    public void issueTest2() {
        try {
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            UUID subjectId = UUID.randomUUID();
            Key key = Key.generateKey(KeyType.IDENTITY);
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            //Capability[] caps = new Capability[] { Capability.GENERIC, Capability.IDENTIFY, Capability.ISSUE };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(key, caps, null);
            Identity identity = iir.issueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), caps, null, null);
            //Identity identity = iir.issueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, Commons.getTrustedKey(), Commons.getTrustedIdentity(), null, caps, null);
            //String k = key.exportToEncoded();
            //String i = identity.exportToEncoded();
            assertEquals(Identity.getTrustedIdentity().getSystemName(), identity.getSystemName());
            assertTrue(subjectId == identity.getSubjectId());
            assertTrue(identity.hasCapability(caps[0]));
            assertTrue(identity.hasCapability(caps[1]));
            assertEquals(key.getPublic(), identity.getPublicKey());
            assertNotNull(identity.getIssuedAt());
            assertNotNull(identity.getExpiresAt());
            assertTrue(identity.getIssuedAt().compareTo(identity.getExpiresAt()) < 0);
            assertTrue(Commons.getIntermediateIdentity().getSubjectId() == identity.getIssuerId());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }
/*
    @Test
    void issueTest3() {
        Identity.SetTrustedIdentity(Commons.TrustedIdentity);
        List<Capability> reqCaps = new List<Capability> { Capability.Issue };
        List<Capability> allowCaps = new List<Capability> { Capability.Generic, Capability.Identify };
        try {
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), reqCaps).Issue(Guid.NewGuid(), 100, Commons.TrustedKey, Commons.TrustedIdentity, allowCaps, null);
        } catch (DimeCapabilityException e) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }
*/

    @Test
    void issueTest4() {
        try {
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            Key key = Key.generateKey(KeyType.IDENTITY);
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), caps, null, null);
            assertTrue(identity.hasCapability(Capability.ISSUE));
            assertTrue(identity.hasCapability(Capability.GENERIC));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }
/*
    @Test
    void issueTest5() {
        Identity.setTrustedIdentity(null);
        Capability[] caps = new Capability[] { Capability.ISSUE };
        try {
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY), caps, null).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), null, caps, null);
        } catch (IllegalArgumentException) { return; } // All is well
        assertTrue(false, "Should not happen.");
    }
*/
    @Test
    void isSelfSignedTest1() {
        try {
            Identity.setTrustedIdentity(null);
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME, null);
            assertTrue(identity.isSelfSigned());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSelfSignedTest2() {
        try {
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY)).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), caps, null, null);
            assertFalse(identity.isSelfSigned());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTrustTest1() {
        try {
            Identity.setTrustedIdentity(null);
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME, null);
            assertTrue(identity.isSelfSigned());
            identity.verifyTrust();
        } catch (IllegalStateException e) { 
            return; // All is well 
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
        assertTrue(false, "This should not happen.");
    }

    @Test
    void verifyTrustTest2() {
        try {
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY)).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), caps, null, null);
            identity.verifyTrust();
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void verifyTrustTest3() {
        try {    
            Identity.setTrustedIdentity(null);
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME, null);
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            identity.verifyTrust();
        } catch (DimeUntrustedIdentityException e) { 
            return; // All is well
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
        assertTrue(false, "This should not happen.");
    }

    @Test
    void verifyTrustTest4() {
        try { 
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            Commons.getIntermediateIdentity().verifyTrust();
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void exportTest1() {
        try { 
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).issueIdentity(UUID.randomUUID(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), caps, null, null);
            String exported = identity.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER + ":" + Identity.TAG));
            assertEquals(4, exported.split("\\.").length);
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void importTest1() {
        try { 
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            String exported = "Di:ID.eyJ1aWQiOiI2YWU2OGE3MC0xN2Y2LTQ1MDQtOWFlMy1jNWJhOWUyZDQ4ZmIiLCJzdWIiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjY4ODgwZmYzLWZlOTQtNGZmMC05MTQ4LTAwYjk4MDgzODg3NyIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloifQ.SUQuZXlKMWFXUWlPaUk1TnpOak16VmhNQzB3WW1Vd0xUUmpOVEV0T0dNMFppMDFaalkzWm1Nd01EYzRNalFpTENKemRXSWlPaUkyT0RnNE1HWm1NeTFtWlRrMExUUm1aakF0T1RFME9DMHdNR0k1T0RBNE16ZzROemNpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWkRNNVpUQmlNREV0TVdabE9DMDBZalkyTFdJeU1EZ3RZbUV4TXpoaU5XVXpPR1F3SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UZFVNVFE2TkRnNk1UWXVOVGswTmpnNFdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MWRVaG5NblUyTW1aNlpFZDVOSGhHUkVKTGNHZGpUWGhPWWt0UVF6UmhTMjUwYmxSeVVYQkhiMmw1YWsxTlFVUlNaaUlzSW1saGRDSTZJakl3TWpFdE1URXRNVGhVTVRRNk5EZzZNVFl1TlRrME5qZzRXaUo5LkRZUVB1NlN0S2dpaTgwYm9FeCtucEhteGhyYW40cGZmMFZ4RTVlTmxPd09UaThTNDhRbGFBM29UTndvMVNKV0JxT09VRStWRnQrMVdENXBZQm5IT0Fn.yoSmBKB/YAWQ68gh//utH8G2szGr1VkRlyvR7kdY5Iy2fHtuL5ynA+0ZsehLv/fk6H8poA0yj/qNFIKLOohtAw";
            Identity identity = Item.importFromEncoded(exported);
            assertNotNull(identity);
            assertEquals(Commons.SYSTEM_NAME, identity.getSystemName());
            assertEquals(UUID.fromString("6ae68a70-17f6-4504-9ae3-c5ba9e2d48fb"), identity.getUniqueId());
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), identity.getSubjectId());
            assertEquals(Instant.parse("2021-11-18T14:51:36.862376Z"), identity.getIssuedAt());
            assertEquals(Instant.parse("2022-11-18T14:51:36.862376Z"), identity.getExpiresAt());
            assertEquals(Commons.getIntermediateIdentity().getSubjectId(), identity.getIssuerId());
            assertEquals("2TDXdoNusvs2c8gGoR4oZc76Ux54sA83bwe7wyrrV6RRYrknZL93nQFfk", identity.getPublicKey());
            assertTrue(identity.hasCapability(Capability.GENERIC));
            assertTrue(identity.hasCapability(Capability.IDENTIFY));
            assertNotNull(identity.getTrustChain());
            identity.verifyTrust();
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

}