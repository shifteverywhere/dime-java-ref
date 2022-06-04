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

import io.dimeformat.enums.KeyUsage;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.Capability;
import io.dimeformat.exceptions.DimeCapabilityException;
import io.dimeformat.exceptions.DimeIntegrityException;
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
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)));
            assertEquals("IIR", iir.getItemIdentifier());
            assertEquals("IIR", IdentityIssuingRequest.ITEM_IDENTIFIER);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateRequestTest1() {
        try {
            IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.EXCHANGE)));
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
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)));
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Key key1 = Key.generateKey(List.of(KeyUsage.SIGN));
            Capability[] caps = new Capability[] { Capability.GENERIC};
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(key1, caps, null);
            String[] components = iir1.exportToEncoded().split("\\.");
            JSONObject json = new JSONObject(new String(Utility.fromBase64(components[1]), StandardCharsets.UTF_8));
            Key key2 = Key.generateKey(List.of(KeyUsage.SIGN));
            json.put("pub", key2.getPublic());
            IdentityIssuingRequest iir2 = Item.importFromEncoded(components[0] + "." + Utility.toBase64(json.toString()) + "." + components[2]);
            assertNotNull(iir2);
            try {
                iir2.issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, caps);
            } catch (DimeIntegrityException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest2() {
         try {
             Capability[] caps = new Capability[] { Capability.GENERIC };
             Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN))).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, caps, null);
             assertNull(identity.getTrustChain());
         } catch (Exception e) {
             fail("Unexpected exception thrown: " + e);
         }
    }

    @Test
    void issueTest3() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN))).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null);
            assertNotNull(identity.getTrustChain());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void issueTest4() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN))).issueIdentity(UUID.randomUUID(), 100, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), false, caps, null);
            assertNull(identity.getTrustChain());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)));
            iir.verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)));
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
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)));
            assertNotEquals(iir1.thumbprint(), iir2.thumbprint(), "Thumbprints of different IIRs should not be the same");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)));
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
            String exported = "Di:IIR.eyJ1aWQiOiIwMmQxOWIyMC01ZDM4LTQzN2YtYmI4ZS01MWRmZDFjNDZhODYiLCJjYXAiOlsiZ2VuZXJpYyJdLCJwdWIiOiJEU1ROK1F5VHlubXNySEE4UGF4WG1ZcG1MVjQ4aFNtU3RHREo5N1BVV2dZd2lYaWtjUTVYVXoiLCJpYXQiOiIyMDIyLTA1LTMwVDE4OjEwOjEyLjEyODYwMVoifQ.isJ89gtjxkGGzI+IxiD9fIvXleqzZDzt25jQd8H/U92MPyG66VbyI8e3EV7RWwe3FvYheOgTe0iO6LrRYsW6Cg";
            IdentityIssuingRequest iir = Item.importFromEncoded(exported);
            assertNotNull(iir);
            assertEquals(UUID.fromString("02d19b20-5d38-437f-bb8e-51dfd1c46a86"), iir.getUniqueId());
            assertEquals(Instant.parse("2022-05-30T18:10:12.128601Z"), iir.getIssuedAt());
            assertTrue(iir.wantsCapability(Capability.GENERIC));
            assertEquals("DSTN+QyTynmsrHA8PaxXmYpmLV48hSmStGDJ97PUWgYwiXikcQ5XUz", iir.getPublicKey().getPublic());
            iir.verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), new Capability[] { Capability.GENERIC, Capability.IDENTIFY });
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] requestedCapabilities = new Capability[] { Capability.GENERIC, Capability.IDENTIFY, Capability.ISSUE };
            Capability[] allowedCapabilities = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), requestedCapabilities);
            try {
                iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, allowedCapabilities, null);
            } catch (DimeCapabilityException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }
 
    @Test
    void capabilityTest3() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] requestedCapabilities = new Capability[] { Capability.GENERIC };
            Capability[] requiredCapabilities = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), requestedCapabilities);
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] requestedCapabilities = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            Capability[] allowedCapabilities = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            Capability[] requiredCapabilities = new Capability[] { Capability.IDENTIFY };
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), requestedCapabilities);
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Capability[] allowedCapabilities = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
            Capability[] requiredCapabilities = new Capability[] { Capability.ISSUE };
            try {
                IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), requiredCapabilities).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), Commons.getTrustedIdentity(), true, allowedCapabilities, null);
            } catch (DimeCapabilityException e) { return; } // All is well
            fail("Should not happen.");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void capabilityTest6() {
        try {
            Dime.setTrustedIdentity(null);
            Capability[] caps = new Capability[] { Capability.ISSUE };
            try {
                IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), caps).issueIdentity(UUID.randomUUID(), 100, Commons.getTrustedKey(), null, true, caps, null);
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
            IdentityIssuingRequest iir =  IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), new Capability[] { Capability.GENERIC }, principles);
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
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN)), new Capability[] { Capability.GENERIC }, principles);
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
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN))).issueIdentity(UUID.randomUUID(), 100L, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null);
            assertEquals(Commons.getIntermediateIdentity().getSystemName(), identity.getSystemName());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void systemNameTest2() {
        try {
            String system = "racecar:is:racecar:backwards";
            Capability[] caps = new Capability[] { Capability.GENERIC };
            Identity identity = IdentityIssuingRequest.generateIIR(Key.generateKey(List.of(KeyUsage.SIGN))).issueIdentity(UUID.randomUUID(), 100L, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, system, null);
            assertNotEquals(Commons.getIntermediateIdentity().getSystemName(), identity.getSystemName());
            assertEquals(system, identity.getSystemName());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}