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
import io.dimeformat.enums.Capability;
import io.dimeformat.enums.KeyType;
import io.dimeformat.exceptions.DimeUntrustedIdentityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps).selfIssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 10, key, Commons.SYSTEM_NAME);
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
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(key, caps);
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

    @Test
    void issueTest3() {
        try {
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            Key key = Key.generateKey(KeyType.IDENTITY);
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), caps, null);
            assertTrue(identity.hasCapability(Capability.ISSUE));
            assertTrue(identity.hasCapability(Capability.GENERIC));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSelfSignedTest1() {
        try {
            Identity.setTrustedIdentity(null);
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
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
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            assertTrue(identity.isSelfSigned());
            identity.verifyTrust();
        } catch (IllegalStateException e) { 
            return; // All is well 
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
        fail("Should not happen.");
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
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            identity.verifyTrust();
        } catch (DimeUntrustedIdentityException e) { 
            return; // All is well
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
        fail("Should not happen.");
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
            Identity identity = Item.importFromEncoded(Commons._encodedIssuerIdentity);
            assertNotNull(identity);
            assertEquals(Commons.SYSTEM_NAME, identity.getSystemName());
            assertEquals(Commons.getIssuerIdentity().getUniqueId(), identity.getUniqueId());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), identity.getSubjectId());
            assertEquals(Commons.getIssuerIdentity().getIssuedAt(), identity.getIssuedAt());
            assertEquals(Commons.getIssuerIdentity().getExpiresAt(), identity.getExpiresAt());
            assertEquals(Commons.getIntermediateIdentity().getSubjectId(), identity.getIssuerId());
            assertEquals(Commons.getIssuerIdentity().getPublicKey(), identity.getPublicKey());
            assertTrue(identity.hasCapability(Capability.GENERIC));
            assertTrue(identity.hasCapability(Capability.IDENTIFY));
            assertNotNull(identity.getTrustChain());
            identity.verifyTrust();
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void ambitTest1() {
        try { 
            String[] ambits = new String[] { "global", "administrator" };
            Key key = Key.generateKey(KeyType.IDENTITY);
            
            Identity identity1 = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME, ambits, null);
            assertEquals(2, identity1.getAmbits().size());
            assertTrue(identity1.hasAmbit(ambits[0]));
            assertTrue(identity1.hasAmbit(ambits[1]));

            Identity identity2 = Item.importFromEncoded(identity1.exportToEncoded());
            assertEquals(2, identity2.getAmbits().size());
            assertTrue(identity2.hasAmbit(ambits[0]));
            assertTrue(identity2.hasAmbit(ambits[1]));
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void methodsTest1() {
        try { 
            String[] methods = new String[] { "dime", "sov" };
            Key key = Key.generateKey(KeyType.IDENTITY);

            Identity identity1 = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME, null, methods);
            List<String> methodList1 = identity1.getMethods();
            assertNotNull(methodList1);
            assertEquals(2, identity1.getMethods().size());
            assertTrue(methodList1.contains(methods[0]));
            assertTrue(methodList1.contains(methods[1]));

            Identity identity2 = Item.importFromEncoded(identity1.exportToEncoded());
            List<String> methodList2 = identity1.getMethods();
            assertNotNull(methodList2);
            assertEquals(2, identity2.getMethods().size());
            assertTrue(methodList2.contains(methods[0]));
            assertTrue(methodList2.contains(methods[1]));
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void principlesTest1() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY);
            Map<String, Object> principles = new HashMap<String, Object>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList(new String[] { "one" , "two", "three" }));
            Identity identity =  IdentityIssuingRequest.generateIIR(key, new Capability[] { Capability.GENERIC }, principles).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            Map<String, Object> pri = identity.getPrinciples();
            assertEquals("Racecar is racecar backwards.", pri.get("tag"));
            List<String> nbr = (List<String>)pri.get("nbr");
            assertEquals(3, nbr.size());
            assertEquals("two", nbr.get(1));
            try {
                pri.put("key", "value");
                fail("Should not happen.");
            } catch (UnsupportedOperationException e) { return; }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void principlesTest2() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY);
            Map<String, Object> principles = new HashMap<String, Object>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList(new String[] { "one" , "two", "three" }));
            Identity identity1 =  IdentityIssuingRequest.generateIIR(key, new Capability[] { Capability.GENERIC }, principles).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            Identity identity2 = Item.importFromEncoded(identity1.exportToEncoded());
            Map<String, Object> pri = identity2.getPrinciples();
            assertEquals("Racecar is racecar backwards.", pri.get("tag"));
            List<String> nbr = (List<String>)pri.get("nbr");
            assertEquals(3, nbr.size());
            assertEquals("three", nbr.get(2));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}