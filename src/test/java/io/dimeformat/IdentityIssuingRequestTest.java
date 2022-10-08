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
import io.dimeformat.exceptions.IntegrityStateException;
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
    void getItemIdentifierTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN));
            assertEquals("IIR", iir.getItemIdentifier());
            assertEquals("IIR", IdentityIssuingRequest.ITEM_IDENTIFIER);
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
            iir.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(iir.getClaim(Claim.CTX));
            iir.putClaim(Claim.EXP, Instant.now());
            assertNotNull(iir.getClaim(Claim.EXP));
            iir.putClaim(Claim.IAT, Instant.now());
            assertNotNull(iir.getClaim(Claim.IAT));
            iir.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(iir.getClaim(Claim.ISS));
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
            try { iir.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
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
            assertNotNull(iir.getUniqueId());
            assertNotNull(iir.getIssuedAt());
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
            try {
                iir2.issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, caps);
                fail("Exception not thrown.");
            } catch (IntegrityStateException e) { /* all is well */ }
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
            String thumbprint = iir.thumbprint();
            //assertTrue(thumbprint != null);
            assertTrue(thumbprint.length() > 0);
            assertEquals(thumbprint, iir.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest2() {
        try {
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)));
            assertNotEquals(iir1.thumbprint(), iir2.thumbprint(), "Thumbprints of different IIRs should not be the same");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyCapability.SIGN)));
            String exported = iir.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Commons.fullHeaderFor(IdentityIssuingRequest.ITEM_IDENTIFIER)));
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
            assertEquals(UUID.fromString("dfa9a8be-60af-4a0f-9efb-027ac61fe75b"), iir.getUniqueId());
            assertEquals(Instant.parse("2022-08-18T20:30:34.721782Z"), iir.getIssuedAt());
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
            assertEquals(Commons.getIntermediateIdentity().getSystemName(), identity.getSystemName());
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
            assertNotEquals(Commons.getIntermediateIdentity().getSystemName(), identity.getSystemName());
            assertEquals(system, identity.getSystemName());
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

}