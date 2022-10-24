//
//  IdentityIssuingRequestTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.IdentityCapability;
import io.dimeformat.exceptions.CapabilityException;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.KeyCapability;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class IdentityTest {

    @Test
    void getHeaderTest1() {
       Identity identity = new Identity();
       assertEquals("ID", identity.getHeader());
       assertEquals("ID", Identity.HEADER);
    }

    @Test
    void claimTest1() {
        try {
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey(), caps).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getAudienceKey(), Commons.SYSTEM_NAME);
            assertNotNull(identity.getClaim(Claim.PUB));
            assertEquals((String) Commons.getAudienceKey().getClaim(Claim.PUB), identity.getClaim(Claim.PUB));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void claimTest2() {
        try {
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey(), caps).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getAudienceKey(), Commons.SYSTEM_NAME);
            identity.strip();
            identity.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(identity.getClaim(Claim.AMB));
            identity.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(identity.getClaim(Claim.AUD));
            identity.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(identity.getClaim(Claim.CTX));
            identity.putClaim(Claim.EXP, Instant.now());
            assertNotNull(identity.getClaim(Claim.EXP));
            identity.putClaim(Claim.IAT, Instant.now());
            assertNotNull(identity.getClaim(Claim.IAT));
            identity.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(identity.getClaim(Claim.ISS));
            identity.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(identity.getClaim(Claim.KID));
            identity.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(identity.getClaim(Claim.MTD));
            Map<String, Object> pri = new HashMap<>();
            pri.put("tag", Commons.PAYLOAD);
            identity.putClaim(Claim.PRI, pri);
            assertNotNull(identity.getClaim(Claim.PRI));
            identity.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(identity.getClaim(Claim.SUB));
            identity.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(identity.getClaim(Claim.SYS));
            identity.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(identity.getClaim(Claim.UID));
            try { identity.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { identity.putClaim(Claim.KEY, Commons.PAYLOAD); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { identity.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { identity.putClaim(Claim.MIM, Commons.MIMETYPE); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { identity.putClaim(Claim.PUB, Commons.getAudienceKey().getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest3() {
        try {
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey(), caps).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getAudienceKey(), Commons.SYSTEM_NAME);
            try { identity.removeClaim(Claim.IAT); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { identity.putClaim(Claim.CTX, Commons.CONTEXT); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey(), caps).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getAudienceKey(), Commons.SYSTEM_NAME);
            identity.strip();
            identity.removeClaim(Claim.IAT);
            identity.putClaim(Claim.CTX, Commons.CONTEXT);
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    public void issueTest1() {
        try {
            Commons.clearKeyRing();
            UUID subjectId = UUID.randomUUID();
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps).selfIssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR, key, Commons.SYSTEM_NAME);
            assertEquals(Commons.SYSTEM_NAME, identity.getClaim(Claim.SYS));
            assertEquals(subjectId, identity.getClaim(Claim.SUB));
            assertEquals(subjectId, identity.getClaim(Claim.ISS));
            assertTrue(identity.hasCapability(caps[0]));
            assertTrue(identity.hasCapability(caps[1]));
            assertTrue(identity.hasCapability(IdentityCapability.SELF));
            assertEquals(key.getPublic(), identity.getPublicKey().getPublic());
            assertNotNull(identity.getClaim(Claim.IAT));
            assertNotNull(identity.getClaim(Claim.EXP));
            assertTrue(((Instant) identity.getClaim(Claim.IAT)).compareTo(identity.getClaim(Claim.EXP)) < 0);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    public void issueTest2() {
        try {
            Commons.initializeKeyRing();
            UUID subjectId = UUID.randomUUID();
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(key, caps);
            Identity identity = iir.issueIdentity(subjectId, Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            assertEquals((String) Commons.getTrustedIdentity().getClaim(Claim.SYS), identity.getClaim(Claim.SYS));
            assertEquals(0, subjectId.compareTo(identity.getClaim(Claim.SUB)));
            assertTrue(identity.hasCapability(caps[0]));
            assertTrue(identity.hasCapability(caps[1]));
            assertEquals(key.getPublic(), identity.getPublicKey().getPublic());
            assertNotNull(identity.getClaim(Claim.IAT));
            assertNotNull(identity.getClaim(Claim.EXP));
            assertTrue(((Instant) identity.getClaim(Claim.IAT)).compareTo(identity.getClaim(Claim.EXP)) < 0);
            assertEquals(0, ((UUID) Commons.getIntermediateIdentity().getClaim(Claim.SUB)).compareTo(identity.getClaim(Claim.ISS)));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest3() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] reqCaps = new IdentityCapability[] { IdentityCapability.ISSUE };
            IdentityCapability[] allowedCaps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            try {
                IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), reqCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, allowedCaps, null);
            } catch (CapabilityException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest4() {
        try {
            Commons.initializeKeyRing();
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, caps, null);
            assertTrue(identity.hasCapability(IdentityCapability.ISSUE));
            assertTrue(identity.hasCapability(IdentityCapability.GENERIC));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest5()
    {
        try {
            Commons.clearKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.ISSUE };
            try {
                IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN), caps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getTrustedKey(), null, true, caps, null);
            } catch (IllegalArgumentException e) {
               /* all is well */
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSelfSignedTest1() {
        try {
            Commons.clearKeyRing();
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME);
            assertTrue(identity.isSelfIssued());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSelfSignedTest2() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            assertFalse(identity.isSelfIssued());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest1() {
        try {
            Commons.clearKeyRing();
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME);
            assertTrue(identity.isSelfIssued());
            assertFalse(identity.verify().isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void verifyTest2() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            assertTrue(identity.verify().isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void verifyTest3() {
        try {
            Commons.clearKeyRing();
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity identity = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME);
            Commons.initializeKeyRing();
            assertFalse(identity.verify().isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void verifyTest4() {
        try {
            Commons.initializeKeyRing();
            Commons.getIntermediateIdentity().verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void verifyTest5() {
        try {
            Commons.initializeKeyRing();
            Commons.getAudienceIdentity().verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest6() {
        try {
            Commons.clearKeyRing();
            Commons.getAudienceIdentity().verify(Commons.getIntermediateIdentity());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest7() {
        Commons.clearKeyRing();
        assertFalse(Commons.getAudienceIdentity().verify(Commons.getIssuerIdentity()).isValid());
    }

    @Test
    void verifyTest8() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] nodeCaps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Key key1 = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity node1 = IdentityIssuingRequest.generateIIR(key1, nodeCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, nodeCaps, nodeCaps);
            Key key2 = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity node2 = IdentityIssuingRequest.generateIIR(key2, nodeCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key1, node1, true, nodeCaps, nodeCaps);
            Key key3 = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity node3 = IdentityIssuingRequest.generateIIR(key3, nodeCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key2, node2, true, nodeCaps, nodeCaps);
            IdentityCapability[] leafCaps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity leaf = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), leafCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key3, node3, true, leafCaps, leafCaps);
            assertTrue(leaf.verify().isValid()); // Verify the whole trust chain and key ring
            assertFalse(leaf.verify(node1).isValid());
            assertFalse(leaf.verify(node2).isValid());
            assertTrue(leaf.verify(node3).isValid()); // verify as issuer
            assertFalse(leaf.verify(Commons.getIntermediateIdentity()).isValid()); // verify as issuer
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest9() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] nodeCaps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.ISSUE };
            Key key1 = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity node1 = IdentityIssuingRequest.generateIIR(key1, nodeCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, nodeCaps, nodeCaps);
            Key key2 = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity node2 = IdentityIssuingRequest.generateIIR(key2, nodeCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key1, node1, true, nodeCaps, nodeCaps);
            IdentityCapability[] leafCaps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity leaf = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), leafCaps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key2, node2, false, leafCaps, leafCaps);
            assertFalse(leaf.verify().isValid());
            assertFalse(leaf.verify(node1).isValid());
            assertTrue(leaf.verify(node2).isValid()); // leaf is missing the trust chain (so cannot be verified towards anything else but the issuer
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest10() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), 1L, Commons.getTrustedKey(), Commons.getTrustedIdentity(), false, caps, caps);
            Thread.sleep(1001);
            assertFalse(identity.verify().isValid(), "(This test may fail if run if the whole test suite is run in parallel)");
            Dime.setGracePeriod(1L);
            assertTrue(identity.verify().isValid());
            Dime.setGracePeriod(0L);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest11() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), 1L, Commons.getTrustedKey(), Commons.getTrustedIdentity(), false, caps, caps);
            Thread.sleep(2000);
            Dime.setTimeModifier(-2);
            assertTrue(identity.verify().isValid(), "(Note this may happen if running tests in parallel)");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest12() {
        try {
            Dime.setTimeModifier(-2);
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), 1L, Commons.getTrustedKey(), Commons.getTrustedIdentity(), false, caps, caps);
            Thread.sleep(2000);
            assertFalse(identity.verify().isValid(), "(This test may fail if run if the whole test suite is run in parallel)");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps, null).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
            String exported = identity.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Commons.fullHeaderFor(Identity.HEADER)));
            assertEquals(4, exported.split("\\.").length);
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void importTest1() {
        try {
            Commons.initializeKeyRing();
            Identity identity = Item.importFromEncoded(Commons._encodedIssuerIdentity);
            assertNotNull(identity);
            assertEquals(Commons.SYSTEM_NAME, identity.getClaim(Claim.SYS));
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.UID), identity.getClaim(Claim.UID));
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), identity.getClaim(Claim.SUB));
            assertEquals((Instant) Commons.getIssuerIdentity().getClaim(Claim.IAT), identity.getClaim(Claim.IAT));
            assertEquals((Instant) Commons.getIssuerIdentity().getClaim(Claim.EXP), identity.getClaim(Claim.EXP));
            assertEquals((UUID) Commons.getIntermediateIdentity().getClaim(Claim.SUB), identity.getClaim(Claim.ISS));
            assertEquals(Commons.getIssuerIdentity().getPublicKey().getPublic(), identity.getPublicKey().getPublic());
            assertTrue(identity.hasCapability(IdentityCapability.GENERIC));
            assertTrue(identity.hasCapability(IdentityCapability.IDENTIFY));
            assertNotNull(identity.getTrustChain());
            identity.verify();
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void ambitTest1() {
        try { 
            String[] ambit = new String[] { "global", "administrator" };
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            
            Identity identity1 = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME, ambit, null);
            List<String> ambit1 = identity1.getClaim(Claim.AMB);
            assertEquals(2, ambit1.size());
            assertTrue(identity1.hasAmbit(ambit[0]));
            assertTrue(identity1.hasAmbit(ambit[1]));

            Identity identity2 = Item.importFromEncoded(identity1.exportToEncoded());
            assertNotNull(identity2);
            List<String> ambit2 = identity2.getClaim(Claim.AMB);
            assertEquals(2, ambit2.size());
            assertTrue(identity2.hasAmbit(ambit[0]));
            assertTrue(identity2.hasAmbit(ambit[1]));
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void methodsTest1() {
        try { 
            String[] methods = new String[] { "dime", "sov" };
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));

            Identity identity1 = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME, null, methods);
            List<String> methods1 = identity1.getClaim(Claim.MTD);
            assertNotNull(methods1);
            assertEquals(2, methods1.size());
            assertTrue(methods1.contains(methods[0]));
            assertTrue(methods1.contains(methods[1]));

            Identity identity2 = Item.importFromEncoded(identity1.exportToEncoded());
            assertNotNull(identity2);
            List<String> methods2 = identity2.getClaim(Claim.MTD);
            assertNotNull(methods2);
            assertEquals(2, methods2.size());
            assertTrue(methods2.contains(methods[0]));
            assertTrue(methods2.contains(methods[1]));
        } catch (Exception e) { 
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void principlesTest1() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Map<String, Object> principles = new HashMap<>();
            principles.put("tag", Commons.PAYLOAD);
            principles.put("nbr", Arrays.asList("one", "two", "three"));
            Identity identity =  IdentityIssuingRequest.generateIIR(key, new IdentityCapability[] { IdentityCapability.GENERIC }, principles).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME);
            Map<String, Object> pri = identity.getPrinciples();
            assertEquals(Commons.PAYLOAD, pri.get("tag"));
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
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Map<String, Object> principles = new HashMap<>();
            principles.put("tag", Commons.PAYLOAD);
            principles.put("nbr", Arrays.asList("one", "two", "three"));
            Identity identity1 =  IdentityIssuingRequest.generateIIR(key, new IdentityCapability[] { IdentityCapability.GENERIC }, principles).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME);
            Identity identity2 = Item.importFromEncoded(identity1.exportToEncoded());
            assertNotNull(identity2);
            Map<String, Object> pri = identity2.getPrinciples();
            assertEquals(Commons.PAYLOAD, pri.get("tag"));
            List<String> nbr = (List<String>)pri.get("nbr");
            assertEquals(3, nbr.size());
            assertEquals("three", nbr.get(2));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
