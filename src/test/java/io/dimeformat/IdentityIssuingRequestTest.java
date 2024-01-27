//
//  IdentityIssuingRequestTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.IdentityCapability;
import io.dimeformat.keyring.IntegrityState;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import io.dimeformat.exceptions.CapabilityException;
import io.dimeformat.enums.KeyCapability;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class IdentityIssuingRequestTest {

    @Test
    void getHeaderTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN));
            assertEquals("IIR", iir.getHeader());
            assertEquals("IIR", IdentityIssuingRequest.HEADER);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void claimTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey());
            assertNotNull(iir.getClaim(Claim.PUB));
            assertEquals((String) Commons.getAudienceKey().getClaim(Claim.PUB), iir.getClaim(Claim.PUB));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void claimTest2() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey());
            iir.strip();
            iir.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(iir.getClaim(Claim.AMB));
            iir.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(iir.getClaim(Claim.AUD));
            iir.putClaim(Claim.CMN, Commons.COMMON_NAME);
            assertNotNull(iir.getClaim(Claim.CMN));
            iir.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(iir.getClaim(Claim.CTX));
            iir.putClaim(Claim.EXP, Instant.now());
            assertNotNull(iir.getClaim(Claim.EXP));
            iir.putClaim(Claim.IAT, Instant.now());
            assertNotNull(iir.getClaim(Claim.IAT));
            iir.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(iir.getClaim(Claim.ISS));
            iir.putClaim(Claim.ISU, Commons.ISSUER_URL);
            assertNotNull(iir.getClaim(Claim.ISU));
            iir.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(iir.getClaim(Claim.KID));
            iir.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(iir.getClaim(Claim.MTD));
            Map<String, Object> pri = new HashMap<>();
            pri.put("tag", Commons.PAYLOAD);
            iir.putClaim(Claim.PRI, pri);
            assertNotNull(iir.getClaim(Claim.PRI));
            iir.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(iir.getClaim(Claim.SUB));
            iir.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(iir.getClaim(Claim.SYS));
            iir.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(iir.getClaim(Claim.UID));
            try { iir.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { iir.putClaim(Claim.KEY, Commons.getIssuerKey().getSecret()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { iir.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey(), Dime.crypto.getDefaultSuiteName())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { iir.putClaim(Claim.MIM, Commons.MIMETYPE); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { iir.putClaim(Claim.PUB, Commons.getAudienceKey().getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest3() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey());
            try { iir.removeClaim(Claim.IAT); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { iir.putClaim(Claim.EXP, Instant.now()); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Commons.getAudienceKey());
            iir.strip();
            iir.removeClaim(Claim.IAT);
            iir.putClaim(Claim.EXP, Instant.now());
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void generateRequestTest1() {
        try {
            IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.EXCHANGE)));
        } catch (IllegalArgumentException e) {
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void generateRequestTest2() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)));
            assertNotNull(iir);
            assertNotNull(iir.getClaim(Claim.UID));
            assertNotNull(iir.getClaim(Claim.IAT));
            assertNotNull(iir.getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest1() {
        try {
            Commons.initializeKeyRing();
            Key key1 = Key.generateKey(List.of(KeyCapability.SIGN));
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(key1, caps, null);
            String[] components = iir1.exportToEncoded().split("\\.");
            JSONObject json = new JSONObject(new String(Utility.fromBase64(components[1]), StandardCharsets.UTF_8));
            Key key2 = Key.generateKey(List.of(KeyCapability.SIGN));
            json.put("pub", key2.getPublic());
            IdentityIssuingRequest iir2 = Item.importFromEncoded(components[0] + "." + Utility.toBase64(json.toString()) + "." + components[2]);
            assertNotNull(iir2);
            assertSame(IntegrityState.FAILED_NOT_TRUSTED, iir2.verify(key1));
            assertSame(IntegrityState.FAILED_KEY_MISMATCH, iir2.verify(key2));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest2() {
         try {
             IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
             Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, caps, null);
             assertNull(identity.getTrustChain());
         } catch (Exception e) {
             fail("Unexpected exception thrown: " + e);
         }
    }

    @Test
    void issueTest3() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null);
            assertNotNull(identity.getTrustChain());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest4() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), false, caps, null);
            assertNull(identity.getTrustChain());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)));
            iir.verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)));
            String thumbprint = iir.generateThumbprint();
            assertFalse(thumbprint.isEmpty());
            assertEquals(thumbprint, iir.generateThumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest2() {
        try {
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN));
            assertNotEquals(iir1.generateThumbprint(), iir2.generateThumbprint(), "Thumbprints of different IIRs should not be the same");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN));
            String exported = iir.exportToEncoded();
            assertNotNull(exported);
            assertFalse(exported.isEmpty());
            assertTrue(exported.startsWith(Commons.fullHeaderFor(IdentityIssuingRequest.HEADER)));
            assertEquals(3, exported.split("\\" + ".").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjMwOjM0LjcyMTc4MloiLCJwdWIiOiJTVE4ucmpYblRNYU02NDI1bVRNNndDV1ZldU1FNG9vclJXMVNpQVNXYWRXYnkxcmR0MldSWSIsInVpZCI6ImRmYTlhOGJlLTYwYWYtNGEwZi05ZWZiLTAyN2FjNjFmZTc1YiJ9.NTBiZjg1NDAxOGU1NjBhZS44Njg3ZThiNmUxNjZlZGIxNTQxZmM2NGJhZTJkODQyMmRiN2FlMjhjYWNkZDVlOTA2ODQ5ZDE4Yjc4NDI4Zjg4NjhhZTRmYTY2ZjcwZmY1YjFiZTI5OGVlYmM2NjgzZDE5MWQ0MDRhMGE4MzQyNzk4MWNmMTBlODk4Yjg5ODAwZQ";
            IdentityIssuingRequest iir = Item.importFromEncoded(exported);
            assertNotNull(iir);
            assertEquals(UUID.fromString("dfa9a8be-60af-4a0f-9efb-027ac61fe75b"), iir.getClaim(Claim.UID));
            assertEquals(Instant.parse("2022-08-18T20:30:34.721782Z"), iir.getClaim(Claim.IAT));
            assertTrue(iir.wantsCapability(IdentityCapability.GENERIC));
            assertEquals("STN.rjXnTMaM6425mTM6wCWVeuME4oorRW1SiASWadWby1rdt2WRY", iir.getPublicKey().getPublic());
            iir.verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest1() {
        try {
            Commons.initializeKeyRing();
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY });
            try {
                iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, null, null);
            } catch (IllegalArgumentException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest2() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] requestedCapabilities = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY, IdentityCapability.ISSUE };
            IdentityCapability[] allowedCapabilities = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), requestedCapabilities);
            try {
                iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, allowedCapabilities, null);
            } catch (CapabilityException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }
 
    @Test
    void capabilityTest3() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] requestedCapabilities = new IdentityCapability[] { IdentityCapability.GENERIC };
            IdentityCapability[] requiredCapabilities = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), requestedCapabilities);
            Identity identity = iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, null, requiredCapabilities);
            assertTrue(identity.hasCapability(requestedCapabilities[0]));
            assertTrue(identity.hasCapability(requiredCapabilities[0]));
            assertEquals(2, identity.getCapabilities().size());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest4() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] requestedCapabilities = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            IdentityCapability[] allowedCapabilities = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            IdentityCapability[] requiredCapabilities = new IdentityCapability[] { IdentityCapability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), requestedCapabilities);
            Identity identity = iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, allowedCapabilities, requiredCapabilities);
            assertTrue(identity.hasCapability(requestedCapabilities[0]));
            assertTrue(identity.hasCapability(requestedCapabilities[1]));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest5() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] allowedCapabilities = new IdentityCapability[] { IdentityCapability.GENERIC, IdentityCapability.IDENTIFY };
            IdentityCapability[] requiredCapabilities = new IdentityCapability[] { IdentityCapability.ISSUE };
            try {
                IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), requiredCapabilities).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, allowedCapabilities, null);
            } catch (CapabilityException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest6() {
        try {
            Commons.clearKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.ISSUE };
            try {
                IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), caps).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getTrustedKey(), null, true, caps, null);
            } catch (IllegalArgumentException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest7() {
        try {
            IdentityCapability[] allCapabilities = new IdentityCapability[] {
                    IdentityCapability.GENERIC,
                    IdentityCapability.IDENTIFY,
                    IdentityCapability.ISSUE,
                    IdentityCapability.PROVE,
                    IdentityCapability.SEAL,
                    IdentityCapability.SELF,
                    IdentityCapability.TIMESTAMP
            };
            Key key = Key.generateKey(KeyCapability.SIGN);
            Identity identity = IdentityIssuingRequest.generateIIR(key, allCapabilities).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME);
            assertTrue(identity.hasCapability(IdentityCapability.GENERIC));
            assertTrue(identity.hasCapability(IdentityCapability.IDENTIFY));
            assertTrue(identity.hasCapability(IdentityCapability.ISSUE));
            assertTrue(identity.hasCapability(IdentityCapability.PROVE));
            assertTrue(identity.hasCapability(IdentityCapability.SEAL));
            assertTrue(identity.hasCapability(IdentityCapability.SELF));
            assertTrue(identity.hasCapability(IdentityCapability.TIMESTAMP));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void principlesTest1() {
        try {
            Map<String, Object> principles = new HashMap<>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList("one", "two", "three"));
            IdentityIssuingRequest iir =  IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), new IdentityCapability[] { IdentityCapability.GENERIC }, principles);
            Map<String, Object> pri = iir.getPrinciples();
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
            Map<String, Object> principles = new HashMap<>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList("one", "two", "three"));
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)), new IdentityCapability[] { IdentityCapability.GENERIC }, principles);
            IdentityIssuingRequest iir2 = Item.importFromEncoded(iir1.exportToEncoded());
            assertNotNull(iir2);
            Map<String, Object> pri = iir2.getPrinciples();
            assertEquals("Racecar is racecar backwards.", pri.get("tag"));
            List<String> nbr = (List<String>)pri.get("nbr");
            assertEquals(3, nbr.size());
            assertEquals("three", nbr.get(2));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void systemNameTest1() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null);
            assertEquals((String) Commons.getIntermediateIdentity().getClaim(Claim.SYS), identity.getClaim(Claim.SYS));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void systemNameTest2() {
        try {
            Commons.initializeKeyRing();
            String system = "racecar:is:racecar:backwards";
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN))).issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, system, null);
            assertNotEquals((String) Commons.getIntermediateIdentity().getClaim(Claim.SYS), identity.getClaim(Claim.SYS));
            assertEquals(system, identity.getClaim(Claim.SYS));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void alienIdentityIssuingRequestTest1() {
        try {
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            String exported = "Di:IIR.eyJ1aWQiOiJmMGMzYTUxZC01MTdlLTQ3ZGQtODJhMy03Y2I2MmJlNDkzNzgiLCJpYXQiOiIyMDIyLTA3LTAxVDA5OjU4OjU5LjAxMzE3N1oiLCJwdWIiOiIyVERYZG9OdVFpQ0o4YWdLckJtRnFNWEF2ZUxBWWNLUVNrY0ZVUkpWSGhvVlB2UkR5M2dNS0xLdnQiLCJjYXAiOlsiZ2VuZXJpYyJdfQ.QCln/lBn5vZa6VvCTo/3IwvUbZXxDGJK4ZUtc9pW5nBHyAMhIz5w2bifuzxCLMHIl1uN3CLR/uFFxpJKG2X6Aw";
            IdentityIssuingRequest iir = Item.importFromEncoded(exported);
            assertNotNull(iir);
            iir.verify();
            Identity identity = iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null);
            assertNotNull(identity);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void keyMismatchIssuingTest1() {
        try {
            // Test to check to that it is not possible to issue an identity with the same public key as the issuing identity
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.ISSUE };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Commons.getIntermediateKey(), caps);
            try {
                iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null);
                fail("Should not happen.");
            }  catch (IllegalArgumentException e) { /* All is well */ }

        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityMismatchIssuingTest1() {
        try {
            // Test to check to that it is not possible to issue an identity with SELF capability if it is not self-issued
            Commons.initializeKeyRing();
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.SELF };
            Key key = Key.generateKey(KeyCapability.SIGN);
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(key, caps);
            try {
                iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null);
                fail("Should not happen.");
            }  catch (IllegalArgumentException e) { /* All is well */ }

        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}