//
//  IdentityIssuingRequestTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeCapabilityException;
import io.dimeformat.exceptions.DimeDateException;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.Capability;
import io.dimeformat.enums.KeyType;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class IdentityTest {

    @Test
    void getItemIdentifierTest1() {
       Identity identity = new Identity();
       assertEquals("ID", identity.getItemIdentifier());
       assertEquals("ID", Identity.ITEM_IDENTIFIER);
    }

    @Test
    public void issueTest1() {
        try {
            Dime.setTrustedIdentity(null);
            UUID subjectId = UUID.randomUUID();
            Key key = Key.generateKey(KeyType.IDENTITY);            
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps).selfIssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, key, Commons.SYSTEM_NAME);
            assertEquals(Commons.SYSTEM_NAME, identity.getSystemName());
            assertEquals(0, subjectId.compareTo(identity.getSubjectId()));
            assertEquals(0, subjectId.compareTo(identity.getIssuerId()));
            assertTrue(identity.hasCapability(caps[0]));
            assertTrue(identity.hasCapability(caps[1]));
            assertTrue(identity.hasCapability(Capability.SELF));
            assertEquals(key.getPublic(), identity.getPublicKey().getPublic());
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            UUID subjectId = UUID.randomUUID();
            Key key = Key.generateKey(KeyType.IDENTITY);
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(key, caps);
            Identity identity = iir.issueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            assertEquals(Dime.getTrustedIdentity().getSystemName(), identity.getSystemName());
            assertEquals(0, subjectId.compareTo(identity.getSubjectId()));
            assertTrue(identity.hasCapability(caps[0]));
            assertTrue(identity.hasCapability(caps[1]));
            assertEquals(key.getPublic(), identity.getPublicKey().getPublic());
            assertNotNull(identity.getIssuedAt());
            assertNotNull(identity.getExpiresAt());
            assertTrue(identity.getIssuedAt().compareTo(identity.getExpiresAt()) < 0);
            assertEquals(0, Commons.getIntermediateIdentity().getSubjectId().compareTo(identity.getIssuerId()));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest3() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] reqCaps = new Capability[] { Capability.ISSUE };
            Capability[] allowedCaps = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            try {
                IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY), reqCaps).issueIdentity(UUID.randomUUID(), 100L, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, allowedCaps, null);
            } catch (DimeCapabilityException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest4() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Key key = Key.generateKey(KeyType.IDENTITY);
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, caps, null);
            assertTrue(identity.hasCapability(Capability.ISSUE));
            assertTrue(identity.hasCapability(Capability.GENERIC));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSelfSignedTest1() {
        try {
            Dime.setTrustedIdentity(null);
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            assertTrue(identity.isSelfIssued());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSelfSignedTest2() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY)).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            assertFalse(identity.isSelfIssued());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest1() {
        try {
            Dime.setTrustedIdentity(null);
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            assertTrue(identity.isSelfIssued());
            identity.isTrusted();
        } catch (IllegalStateException e) {
            return; // All is well 
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
        fail("Should not happen.");
    }

    @Test
    void isTrustedTest2() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY)).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            assertTrue(identity.isTrusted());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void isTrustedTest3() {
        try {
            Dime.setTrustedIdentity(null);
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            assertFalse(identity.isTrusted());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void isTrustedTest4() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            assertTrue(Commons.getIntermediateIdentity().isTrusted());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void isTrustedTest5() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            assertTrue(Commons.getAudienceIdentity().isTrusted());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest6() {
        try {
            Dime.setTrustedIdentity(null);
            assertTrue(Commons.getAudienceIdentity().isTrusted(Commons.getIntermediateIdentity()));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest7() {
        try {
            Dime.setTrustedIdentity(null);
            assertFalse(Commons.getAudienceIdentity().isTrusted(Commons.getIssuerIdentity()));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest8() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] nodeCaps = new Capability[] { Capability.GENERIC, Capability.ISSUE };
            Key key1 = Key.generateKey(KeyType.IDENTITY);
            Identity node1 = IdentityIssuingRequest.generateIIR(key1, nodeCaps).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, nodeCaps, nodeCaps);
            Key key2 = Key.generateKey(KeyType.IDENTITY);
            Identity node2 = IdentityIssuingRequest.generateIIR(key2, nodeCaps).issueIdentity(UUID.randomUUID(), 100, key1, node1, true, nodeCaps, nodeCaps);
            Key key3 = Key.generateKey(KeyType.IDENTITY);
            Identity node3 = IdentityIssuingRequest.generateIIR(key3, nodeCaps).issueIdentity(UUID.randomUUID(), 100, key2, node2, true, nodeCaps, nodeCaps);
            Capability[] leafCaps = new Capability[] { Capability.GENERIC };
            Identity leaf = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY), leafCaps).issueIdentity(UUID.randomUUID(), 100, key3, node3, true, leafCaps, leafCaps);
            assertTrue(leaf.isTrusted());
            assertTrue(leaf.isTrusted(node1));
            assertTrue(leaf.isTrusted(node2));
            assertTrue(leaf.isTrusted(node3));
            assertFalse(leaf.isTrusted(Commons.getIntermediateIdentity()));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest9() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] nodeCaps = new Capability[] { Capability.GENERIC, Capability.ISSUE };
            Key key1 = Key.generateKey(KeyType.IDENTITY);
            Identity node1 = IdentityIssuingRequest.generateIIR(key1, nodeCaps).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), false, nodeCaps, nodeCaps);
            Key key2 = Key.generateKey(KeyType.IDENTITY);
            Identity node2 = IdentityIssuingRequest.generateIIR(key2, nodeCaps).issueIdentity(UUID.randomUUID(), 100, key1, node1, false, nodeCaps, nodeCaps);
            Capability[] leafCaps = new Capability[] { Capability.GENERIC };
            Identity leaf = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY), leafCaps).issueIdentity(UUID.randomUUID(), 100, key2, node2, false, leafCaps, leafCaps);
            assertFalse(leaf.isTrusted());
            assertFalse(leaf.isTrusted(node1));
            assertTrue(leaf.isTrusted(node2));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest10() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY)).issueIdentity(UUID.randomUUID(), 1, Commons.getTrustedKey(), Commons.getTrustedIdentity(), false, caps, caps);
            Thread.sleep(1000);
            try {
                identity.isTrusted();
                fail("Exception should have been thrown.");
            } catch (DimeDateException e) { /* All is good */ }
            identity.isTrusted(1);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest11() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY)).issueIdentity(UUID.randomUUID(), 1, Commons.getTrustedKey(), Commons.getTrustedIdentity(), false, caps, caps);
            Thread.sleep(2000);
            Dime.setTimeModifier(-2);
            identity.isTrusted();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isTrustedTest12() {
        try {
            Dime.setTimeModifier(-2);
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY)).issueIdentity(UUID.randomUUID(), 1, Commons.getTrustedKey(), Commons.getTrustedIdentity(), false, caps, caps);
            Thread.sleep(2000);
            identity.isTrusted();
        } catch (DimeDateException e) {
            // All is good
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).issueIdentity(UUID.randomUUID(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            String exported = identity.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER + ":" + Identity.ITEM_IDENTIFIER));
            assertEquals(4, exported.split("\\.").length);
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void importTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Identity identity = Item.importFromEncoded(Commons._encodedIssuerIdentity);
            assertNotNull(identity);
            assertEquals(Commons.SYSTEM_NAME, identity.getSystemName());
            assertEquals(Commons.getIssuerIdentity().getUniqueId(), identity.getUniqueId());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), identity.getSubjectId());
            assertEquals(Commons.getIssuerIdentity().getIssuedAt(), identity.getIssuedAt());
            assertEquals(Commons.getIssuerIdentity().getExpiresAt(), identity.getExpiresAt());
            assertEquals(Commons.getIntermediateIdentity().getSubjectId(), identity.getIssuerId());
            assertEquals(Commons.getIssuerIdentity().getPublicKey().getPublic(), identity.getPublicKey().getPublic());
            assertTrue(identity.hasCapability(Capability.GENERIC));
            assertTrue(identity.hasCapability(Capability.IDENTIFY));
            assertNotNull(identity.getTrustChain());
            assertTrue(identity.isTrusted());
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
            assertNotNull(identity2);
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
            assertNotNull(identity2);
            List<String> methodList2 = identity2.getMethods();
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
            Map<String, Object> principles = new HashMap<>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList("one", "two", "three"));
            Identity identity =  IdentityIssuingRequest.generateIIR(key, new Capability[] { Capability.GENERIC }, principles).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            Map<String, Object> pri = identity.getPrinciples();
            assertEquals("Racecar is racecar backwards.", pri.get("tag"));
            List<String> nbr = (List<String>)pri.get("nbr");
            assertEquals(3, nbr.size());
            assertEquals("two", nbr.get(1));
            try {
                pri.put("key", "value");
                fail("Should not happen.");
            } catch (UnsupportedOperationException e) { /* All is good */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void principlesTest2() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY);
            Map<String, Object> principles = new HashMap<>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList("one", "two", "three"));
            Identity identity1 =  IdentityIssuingRequest.generateIIR(key, new Capability[] { Capability.GENERIC }, principles).selfIssueIdentity(UUID.randomUUID(), 100, key, Commons.SYSTEM_NAME);
            Identity identity2 = Item.importFromEncoded(identity1.exportToEncoded());
            assertNotNull(identity2);
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