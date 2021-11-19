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
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class IdentityIssuingRequestTest {

    @Test
    void getTagTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
            assertEquals("IIR", iir.getTag());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateRequestTest1() {
        try {
            IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.EXCHANGE));
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
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
            assertNotNull(iir);
            assertNotNull(iir.getUniqueId());
            assertNotNull(iir.getIssuedAt());
            assertNotNull(iir.getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
            iir.verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
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
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
            assertNotEquals(iir1.thumbprint(), iir2.thumbprint(), "Thumbprints of different iirs should not be the same");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR( Key.generateKey(KeyType.IDENTITY));
            String exported = iir.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER + ":" +IdentityIssuingRequest.TAG));
            assertTrue(exported.split("\\" + ".").length == 3);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di:IIR.eyJ1aWQiOiIzZTViZGU0YS02Mjc3LTRkYTUtODY2NC0xZDNmMDQzYTkwMjgiLCJjYXAiOlsiZ2VuZXJpYyJdLCJwdWIiOiIyVERYZG9OdlNVTnlMRFNVaU1ocExDZEViRGF6NXp1bUQzNXRYMURBdUE4Q0U0MXhvREdnU2QzVUUiLCJpYXQiOiIyMDIxLTExLTE4VDEyOjAzOjUzLjM4MTY2MVoifQ.13/fVQLNOMbnHQXIE//T9PWnE0reDR0LVJUugy3SZ8J7g68idwutFqEGUiTwlPz/t0Ci1IU46kI+ftA83cc2AA";
            IdentityIssuingRequest iir = Item.importFromEncoded(exported);
            assertNotNull(iir);
            assertEquals(UUID.fromString("3e5bde4a-6277-4da5-8664-1d3f043a9028"), iir.getUniqueId());
            assertEquals(Instant.parse("2021-11-18T12:03:53.381661Z"), iir.getIssuedAt());
            assertTrue(iir.wantsCapability(Capability.GENERIC));
            assertEquals("2TDXdoNvSUNyLDSUiMhpLCdEbDaz5zumD35tX1DAuA8CE41xoDGgSd3UE", iir.getPublicKey());
            iir.verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }
/*
    @Test
    void capabilityTest1() {
        Identity.SetTrustedIdentity(Commons.TrustedIdentity);
        List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
        IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
        try
        {
            Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, null);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

        [TestMethod]
    public void CapabilityTest2()
    {
        Identity.SetTrustedIdentity(Commons.TrustedIdentity);
        List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
        List<Capability> allowedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
        IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
        try
        {
            Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, allowedCapabilities);
        } catch (IdentityCapabilityException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

        [TestMethod]
    public void CapabilityTest3()
    {
        Identity.SetTrustedIdentity(Commons.TrustedIdentity);
        List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic };
        List<Capability> allowedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
        List<Capability> requiredCapabilities = new List<Capability> { Capability.Identify };
        IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
        try
        {
            Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, allowedCapabilities, requiredCapabilities);
        } catch (IdentityCapabilityException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

        [TestMethod]
    public void CapabilityTest4()
    {
        Identity.SetTrustedIdentity(Commons.TrustedIdentity);
        List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
        List<Capability> allowedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
        List<Capability> requiredCapabilities = new List<Capability> { Capability.Identify };
        IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
        Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, allowedCapabilities, requiredCapabilities);
        Assert.IsTrue(identity.HasCapability(requestedCapabilities[0]));
        Assert.IsTrue(identity.HasCapability(requestedCapabilities[1]));
    }

}
*/
    @Test
    void principlesTest1() {
        try {
            Map<String, Object> principles = new HashMap<String, Object>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList(new String[] { "one" , "two", "three" }));
            IdentityIssuingRequest iir =  IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY), new Capability[] { Capability.GENERIC }, principles);
            Map<String, Object> pri = iir.getPrinciples();
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
            Map<String, Object> principles = new HashMap<String, Object>();
            principles.put("tag", "Racecar is racecar backwards.");
            principles.put("nbr", Arrays.asList(new String[] { "one" , "two", "three" }));
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY), new Capability[] { Capability.GENERIC }, principles);
            IdentityIssuingRequest iir2 = Item.importFromEncoded(iir1.exportToEncoded());
            Map<String, Object> pri = iir2.getPrinciples();
            assertEquals("Racecar is racecar backwards.", pri.get("tag"));
            List<String> nbr = (List<String>)pri.get("nbr");
            assertEquals(3, nbr.size());
            assertEquals("three", nbr.get(2));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}