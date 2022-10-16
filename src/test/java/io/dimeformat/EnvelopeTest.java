//
//  CryptoTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyCapability;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeTest {

    @Test
    void getHeaderTest1() {
        Envelope envelope = new Envelope();
        assertEquals("Di", envelope.getHeader());
        assertEquals("Di", Envelope.HEADER);
    }

    @Test
    void claimTest1() {
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        assertNotNull(envelope.getClaim(Claim.ISS));
        assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
    }

    @Test
    void claimTest2() {
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB), Commons.CONTEXT);
        assertNotNull(envelope.getClaim(Claim.CTX));
        assertEquals(Commons.CONTEXT, envelope.getClaim(Claim.CTX));
        envelope.removeClaim(Claim.CTX);
        assertNull(envelope.getClaim(Claim.CTX));
    }

    @Test
    void claimTest3() {
        try {
            Envelope envelope = new Envelope();
            envelope.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(envelope.getClaim(Claim.AMB));
            envelope.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(envelope.getClaim(Claim.AUD));
            envelope.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(envelope.getClaim(Claim.CTX));
            envelope.putClaim(Claim.EXP, Instant.now());
            assertNotNull(envelope.getClaim(Claim.EXP));
            envelope.putClaim(Claim.IAT, Instant.now());
            assertNotNull(envelope.getClaim(Claim.IAT));
            envelope.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(envelope.getClaim(Claim.ISS));
            envelope.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(envelope.getClaim(Claim.KID));
            envelope.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(envelope.getClaim(Claim.MTD));
            envelope.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(envelope.getClaim(Claim.SUB));
            envelope.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(envelope.getClaim(Claim.SYS));
            envelope.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(envelope.getClaim(Claim.UID));
            try { envelope.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { envelope.putClaim(Claim.KEY, Commons.getIssuerKey().getSecret()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { envelope.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { envelope.putClaim(Claim.MIM, Commons.MIMETYPE); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { Map<String, Object> pri = new HashMap<>(); pri.put("tag", Commons.PAYLOAD); envelope.putClaim(Claim.PRI, pri); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { envelope.putClaim(Claim.PUB, Commons.getIssuerKey().getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope.addItem(Commons.getIssuerKey().publicCopy());
            envelope.sign(Commons.getIssuerKey());
            try { envelope.removeClaim(Claim.ISS); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { envelope.putClaim(Claim.EXP, Instant.now()); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest5() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope.addItem(Commons.getIssuerKey().publicCopy());
            envelope.sign(Commons.getIssuerKey());
            envelope.strip();
            envelope.removeClaim(Claim.ISS);
            envelope.putClaim(Claim.IAT, Instant.now());
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void getItemTest1() {
        try {
            Message message = new Message(UUID.randomUUID(), UUID.randomUUID(), Dime.NO_EXPIRATION, "message-context");
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), "key-context");
            Envelope envelope = new Envelope();
            envelope.addItem(message);
            envelope.addItem(key);
            // Context
            Item item1 = envelope.getItem("key-context");
            assertTrue(item1 instanceof Key);
            assertEquals("key-context", item1.getClaim(Claim.CTX));
            Item item2 = envelope.getItem("message-context");
            assertTrue(item2 instanceof Message);
            assertEquals("message-context", item2.getClaim(Claim.CTX));
            // Unique ID
            Item item3 = envelope.getItem((UUID) key.getClaim(Claim.UID));
            assertTrue(item3 instanceof Key);
            assertEquals((UUID) key.getClaim(Claim.UID), item3.getClaim(Claim.UID));
            Item item4 = envelope.getItem((UUID) message.getClaim(Claim.UID));
            assertTrue(item4 instanceof Message);
            assertEquals((UUID) message.getClaim(Claim.UID), item4.getClaim(Claim.UID));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void getItemTest2() {
        try {
            String exported = "Di:MSG.eyJpc3MiOiJkMThhM2ExYi05Y2I2LTQ4MGEtYTJlZC05NGU2NzMwZTVlMzQiLCJ1aWQiOiIwYTQ2YWVkNy0yYzkyLTQwNDQtYmMyMC0yMTc0Y2IwNjA0MmQiLCJhdWQiOiI3YTAyMzkzZS1kMTVkLTQ3NDYtOTU0Mi1hZDljYmUwNzUxYzgiLCJpYXQiOiIyMDIyLTA1LTMwVDE3OjI1OjMxLjQ0NjkxNloiLCJjdHgiOiJtZXNzYWdlLWNvbnRleHQifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.EBiQVW1sKZgKXEg0qDNoxXGUZXhvO8NfxMWn9YL8zhkVU7jp3q2a8p+5dzlRW1AJXwVdk7iH1jhJMux0DGbpBg:KEY.eyJ1aWQiOiIxMWYxNzllZi0yOWIwLTRlZjAtYjA0Yi0xZjU3MTk5ZTJjZjQiLCJwdWIiOiJTVE4rMk5taUIxdlVQSFNDMnplbzZZZzlEQlNTNFdYU3dFSDNLclUxelRCamg4dlV0S3h4WUQiLCJpYXQiOiIyMDIyLTA1LTMwVDE3OjI1OjMxLjcyNzcwNFoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJrZXktY29udGV4dCIsImtleSI6IlNUTithRFp0c2FIaW9nb1R1OW1YdTZqWmJjTG94alE4aFpQaDJ4Rm5SUXhidlRLb1R3YkFLdGFldWRBRFA0dk1US25uRHNtYUcyc3RxeGZaM2hGNXdtWDMzV2V6UFRINFkifQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            // Context
            Item item1 = envelope.getItem("key-context");
            assertTrue(item1 instanceof Key);
            assertEquals("key-context", item1.getClaim(Claim.CTX));
            Item item2 = envelope.getItem("message-context");
            assertTrue(item2 instanceof Message);
            assertEquals("message-context", item2.getClaim(Claim.CTX));
            // Unique ID
            UUID uid1 = UUID.fromString("11f179ef-29b0-4ef0-b04b-1f57199e2cf4");
            Item item3 = envelope.getItem(uid1);
            assertTrue(item3 instanceof Key);
            assertEquals(uid1, item3.getClaim(Claim.UID));
            UUID uid2 = UUID.fromString("0a46aed7-2c92-4044-bc20-2174cb06042d");
            Item item4 = envelope.getItem(uid2);
            assertTrue(item4 instanceof Message);
            assertEquals(uid2, item4.getClaim(Claim.UID));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void getItemTest3() {
        Envelope envelope = new Envelope();
        envelope.addItem(Key.generateKey(List.of(KeyCapability.SIGN)));
        assertNull(envelope.getItem((String)null));
        assertNull(envelope.getItem(""));
        assertNull(envelope.getItem("invalid-context"));
        assertNull(envelope.getItem((UUID)null));
        assertNull(envelope.getItem(UUID.randomUUID()));
    }

    @Test
    void signTest1() {
        Envelope envelope = new Envelope();
        try {
            envelope.sign(Commons.getIssuerKey());
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
        fail("Should not happen.");
    }

    @Test
    void signTest2() {
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        try {
            envelope.sign(Commons.getIssuerKey());
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
        fail("Should not happen.");
    }

    @Test
    void signTest3() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB), context);
        assertEquals(context, envelope.getClaim(Claim.CTX));
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB), context);
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            envelope1.addItem(message);
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();
            Envelope envelope2 = Envelope.importFromEncoded(exported);
            assertEquals(context, envelope2.getClaim(Claim.CTX));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB), context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void thumbprintTest1() {
        try {
            Envelope envelope = new Envelope();
            envelope.addItem(Commons.getIssuerKey());
            assertNotNull(envelope.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest2(){
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
            assertNotNull(envelope.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest3() {
        try {
            Envelope envelope1 = new Envelope();
            envelope1.addItem(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();
            Envelope envelope2 = Envelope.importFromEncoded(exported);
            assertEquals(envelope1.thumbprint(), envelope2.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest4() {
        try {
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope1.addItem(Commons.getIssuerKey());
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();
            Envelope envelope2 = Envelope.importFromEncoded(exported);
            assertEquals(envelope1.thumbprint(), envelope2.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest5() {
        try {
            Envelope envelope = new Envelope();
            envelope.addItem(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertEquals(envelope.thumbprint(), Envelope.thumbprint(exported));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest6() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertEquals(envelope.thumbprint(), Envelope.thumbprint(exported));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void iirExportTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN));
            Envelope envelope = new Envelope();
            envelope.addItem(iir);
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(2, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    public void iirImportTest1() {
        try {
            String exported = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjI1OjIzLjQ1NTEwMFoiLCJwdWIiOiJTVE4uWVptcHlUdGpnWGdXYndBZmRNdmtUMXVGeUVVNG5qVVdQalFTaW1kU1NTQVZldlVHcSIsInVpZCI6IjM4YjYzNDY3LTU5YjUtNDc0ZC1hMGZiLTZjMWRiYjEyNWQ0NSJ9.YjAwNGE0NzdiYzUyN2JjYi4zYzBjOTk0MzEyYzAxZDM5ZTBlM2Q4YTA3NDRjODE1YmZiYjBhZjg5YTRhNWQ0ODZiODVmNGFhODM1YjA0Mzg4NzEyYjU5MWIyYzRjNGIyZWY4MWRiNTZiMzM0MzhiOGMwOTgzZDdmNDFmMmU3ZDAyNDQwMjFkNGUwZThjMzkwZg";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertTrue(envelope.isAnonymous());
            assertNull(envelope.getClaim(Claim.ISS));
            assertEquals(1, envelope.getItems().size());
            assertEquals(IdentityIssuingRequest.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope.addItem(Commons.getIssuerIdentity());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityExportTest2() {
        Envelope envelope = new Envelope();
        envelope.addItem(Commons.getIssuerIdentity());
        String exported = envelope.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.length() > 0);
        assertTrue(exported.startsWith(Envelope.HEADER));
        assertEquals(2, exported.split(":").length);
    }

    @Test
    void identityImportTest1() {
        try {
            String exported = "Di.eyJpYXQiOiIyMDIyLTEwLTAzVDE3OjMxOjA2Ljg1ODc2OFoiLCJpc3MiOiJlZjRkNWJmMC1mOWVkLTQzZTktYmE3ZC0wMGNkNDEwYzJmMmMifQ:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMDNUMTQ6NDE6NTMuMTQ5Njk0WiIsImlhdCI6IjIwMjItMTAtMDNUMTQ6NDE6NTMuMTQ5Njk0WiIsImlzcyI6ImNlNTc4YjM2LWJhMmMtNGNmMS1hZTVjLTM3YzU2NWFmNmUxMSIsInB1YiI6IlNUTi4yS1ZRTVNGQmdEeEF0MkZ3ZjI3TnRnOXd0OVd5NlhuNnJtWDQ4Y1l6clJrNTVUMkZQbSIsInN1YiI6ImVmNGQ1YmYwLWY5ZWQtNDNlOS1iYTdkLTAwY2Q0MTBjMmYyYyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiY2ZkODFlZjktMjExNy00NGEyLWIwMWEtZDUyOTUxZGVjN2UxIn0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB3TWxReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB3TTFReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFYTnpJam9pWWpRell6UTRNamd0TURrMk1TMDBZbVEyTFdJM1lXTXRaVGMyWWprNE9HSmhabVl3SWl3aWNIVmlJam9pVTFST0xtMXJWVTF2WjJWdmFGVTVRM1YxY0RsVlYzWnhNVEo2VTI5Vk5qUmxURlZYVlZoeE1UbG1PWEJaU2pOaFNsWkdVRU1pTENKemRXSWlPaUpqWlRVM09HSXpOaTFpWVRKakxUUmpaakV0WVdVMVl5MHpOMk0xTmpWaFpqWmxNVEVpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJalV5T1RNMlptUTBMV1ZtTldNdE5EbGxOUzA1T1RreUxUSmxaVEJsWkRBeFpETXdNaUo5Lk1qWTNNRFUzWm1RNU4yVXlNRE5tTmk1all6TTNNbU5rWTJFek1EQmtaRFU1TkRZMk5HWmhNMkUxWXpaa00yUTFNakpqTmpSbE9EbG1NalE1TmpjME9EVXdNamN3TlRReFkyVXlOalZrTUdOalpUVmhaVFJsTmpFMk1tUTNNREpqTURFNE1tWTJZalUyTkRKa09ERTVOREUxTW1Oa056ZzNZMlkxTlRFd056Qm1abVV4Tm1aaU0yRXpOemcxTXpFd05B.MDFiODQxNmIzMjk0NmJmYi43ZDFlZjgwMWQ5YWIyMzQ0ZGZiMTQxODhjZTZiZWU0Yjk4MTNjYzJmZjI4NzNlNzQ3Mzc5NDBkMjViNDc4ZDk0MTY5MjlkM2I1ZWMzNjUwMTY3MzIxN2MwZjk4ZTA4MTM4ZGNiMGJmZGJjYzFkOWYzNTU2OTg5MDI1OTRmOGYwNQ:YjkyMjMwYzBkNTY0YjU0NS5lMjM5MTRhY2I3YTViNGU4ZmE1MjU4MzgxMGZmNmI5YzA1MDIyNjY1MjcwNDJhZTczYTVjZDZkOTU2MDhlYTE3ZDhlMDhmZmI2MWNhODhmNjQwNjJjM2ZmODM2ZDY3NGJmMDE3MGJkMjNjYTgwNTA5ZjI1ZDEwM2UyZWM1ODcwZg";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2022-10-03T17:31:06.858768Z"), envelope.getClaim(Claim.IAT));
            assertNull(envelope.getClaim(Claim.CTX));
            assertEquals(1, envelope.getItems().size());
            assertEquals(Identity.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityImportTest2() {
        try {
            String exported = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMDNUMTQ6NDE6NTMuMTQ5Njk0WiIsImlhdCI6IjIwMjItMTAtMDNUMTQ6NDE6NTMuMTQ5Njk0WiIsImlzcyI6ImNlNTc4YjM2LWJhMmMtNGNmMS1hZTVjLTM3YzU2NWFmNmUxMSIsInB1YiI6IlNUTi4yS1ZRTVNGQmdEeEF0MkZ3ZjI3TnRnOXd0OVd5NlhuNnJtWDQ4Y1l6clJrNTVUMkZQbSIsInN1YiI6ImVmNGQ1YmYwLWY5ZWQtNDNlOS1iYTdkLTAwY2Q0MTBjMmYyYyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiY2ZkODFlZjktMjExNy00NGEyLWIwMWEtZDUyOTUxZGVjN2UxIn0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB3TWxReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB3TTFReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFYTnpJam9pWWpRell6UTRNamd0TURrMk1TMDBZbVEyTFdJM1lXTXRaVGMyWWprNE9HSmhabVl3SWl3aWNIVmlJam9pVTFST0xtMXJWVTF2WjJWdmFGVTVRM1YxY0RsVlYzWnhNVEo2VTI5Vk5qUmxURlZYVlZoeE1UbG1PWEJaU2pOaFNsWkdVRU1pTENKemRXSWlPaUpqWlRVM09HSXpOaTFpWVRKakxUUmpaakV0WVdVMVl5MHpOMk0xTmpWaFpqWmxNVEVpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJalV5T1RNMlptUTBMV1ZtTldNdE5EbGxOUzA1T1RreUxUSmxaVEJsWkRBeFpETXdNaUo5Lk1qWTNNRFUzWm1RNU4yVXlNRE5tTmk1all6TTNNbU5rWTJFek1EQmtaRFU1TkRZMk5HWmhNMkUxWXpaa00yUTFNakpqTmpSbE9EbG1NalE1TmpjME9EVXdNamN3TlRReFkyVXlOalZrTUdOalpUVmhaVFJsTmpFMk1tUTNNREpqTURFNE1tWTJZalUyTkRKa09ERTVOREUxTW1Oa056ZzNZMlkxTlRFd056Qm1abVV4Tm1aaU0yRXpOemcxTXpFd05B.MDFiODQxNmIzMjk0NmJmYi43ZDFlZjgwMWQ5YWIyMzQ0ZGZiMTQxODhjZTZiZWU0Yjk4MTNjYzJmZjI4NzNlNzQ3Mzc5NDBkMjViNDc4ZDk0MTY5MjlkM2I1ZWMzNjUwMTY3MzIxN2MwZjk4ZTA4MTM4ZGNiMGJmZGJjYzFkOWYzNTU2OTg5MDI1OTRmOGYwNQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertTrue(envelope.isAnonymous());
            assertNull(envelope.getClaim(Claim.ISS));
            assertEquals(1, envelope.getItems().size());
            assertEquals(Identity.class, envelope.getItems().get(0).getClass());
            assertFalse(envelope.verify(Commons.getIssuerKey()).isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void keyExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void keyImportTest1() {
        try {
            String exported = "Di.eyJpYXQiOiIyMDIyLTEwLTAzVDE3OjMyOjM0Ljk2MzYzM1oiLCJpc3MiOiJlZjRkNWJmMC1mOWVkLTQzZTktYmE3ZC0wMGNkNDEwYzJmMmMifQ:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjE0NjgxN1oiLCJrZXkiOiJTVE4uNjZXbXBGSjQ2NXREcVFMZHBKMVBWdk5MZ1Q3OUhSTVRLa0U3ZjlKTEF3NDdBb29GNUo5eFRibVBvQ25haFNpSk40TldXR3E0UlVya0w5NFVnNnBUVERoTFNuZkozIiwicHViIjoiU1ROLjJLVlFNU0ZCZ0R4QXQyRndmMjdOdGc5d3Q5V3k2WG42cm1YNDhjWXpyUms1NVQyRlBtIiwidWlkIjoiNDY4MDFmMjktODU1Ny00OWFhLWJiNTctNTBlZmRiMjhkZmZmIn0:YjkyMjMwYzBkNTY0YjU0NS5kNDliYWY0Y2M3YTUwMjcwZDg3NGY4MWIwYmY2MDcxOTNjMGJmYTA1NDgzNGNkZDk5ZmMxNzQ5NDc1ODdjNjdmOTNmOGM2Y2Q3Y2MwMzkxZDY0YjVlZWNmMWJmNTU5YzY5MGVkODUyNzNkM2Y4NmE4ZGY1NGQ2YTM5MjVhMTUwOQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2022-10-03T17:32:34.963633Z"), envelope.getClaim(Claim.IAT));
            assertNull(envelope.getClaim(Claim.CTX));
            assertEquals(1, envelope.getItems().size());
            assertEquals(Key.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void dataExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB), Commons.CONTEXT);
            Data data = new Data(Commons.getAudienceIdentity().getClaim(Claim.SUB),100);
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
            data.sign(Commons.getIssuerKey());
            envelope.addItem(data);
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void dataImportTest1() {
        try {
            String exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTEwLTAzVDE3OjMzOjE4LjUwMTc0NFoiLCJpc3MiOiJlZjRkNWJmMC1mOWVkLTQzZTktYmE3ZC0wMGNkNDEwYzJmMmMifQ:DAT.eyJleHAiOiIyMDIyLTEwLTAzVDE3OjM0OjU4LjUwMzU3M1oiLCJpYXQiOiIyMDIyLTEwLTAzVDE3OjMzOjE4LjUwMzU3M1oiLCJpc3MiOiJjYzMwNWY3NC02MWRjLTRlY2UtYmQ1MC1jYTg4NWQwYzM2OWYiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiMGQxNmM4MjgtNTdlNy00YWVlLWFkZjctNjdkOThjYjBiZjcyIn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.YjkyMjMwYzBkNTY0YjU0NS5hYzBmZWFjMTc5N2ZlMWIzYzdhMDI3Y2U4MWRiMmI4MGVjNDczNzA3MjFkYTI5MGM3NTk5NTM3OWRkYmYxOGVlZjAwYWYxYjA2NjRiMGUzOGQ2ZTNhMjQ1ODhhMDlmZGRmZDdmMTE4NmM1NzNmOTkwZWNiYTQ3ZjdmMWE1ODAwOQ:YjkyMjMwYzBkNTY0YjU0NS41MDEyNjczZGE4Zjg2ZjFmZTFkZjY2NjE4ZmI0NjI3MjQ0ZjA2ZTc3NWZkZDA5MDc2ZTRlOTAwZDY1ZjhhMmExMTAzNjZhOTE0OTQ4Y2NlZDEyOTIyMzQ4ZGI2ZTQ3MDEwNzliOTNjMGM4YTAxYzY2YjdkOTJhOTZjYTM1ZDcwYg";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2022-10-03T17:33:18.501744Z"), envelope.getClaim(Claim.IAT));
            assertEquals(Commons.CONTEXT, envelope.getClaim(Claim.CTX));
            assertEquals(1, envelope.getItems().size());
            assertEquals(Data.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void messageExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB), "Di:ME");
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            envelope.addItem(message);
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void messageImportTest1() {
        try {
            String exported = "Di.eyJjdHgiOiJEaTpNRSIsImlzcyI6IjBhYTU2MTMzLTc4YjAtNGRkOS05MjhkLTVkN2ZmOWRhNTQ0NSIsImlhdCI6IjIwMjEtMTEtMThUMjA6MDM6MTguMTc2MDI4WiJ9:MSG.eyJ1aWQiOiI5ZDFiNzAyYy1lODQwLTRjZDYtYTNiNy0zZDRlODJjMjY5N2YiLCJhdWQiOiJhNjkwMjE4NC0yYmEwLTRiYTAtYWI5MS1jYTc3ZGE3ZDA1ZDMiLCJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJleHAiOiIyMDIxLTExLTE4VDIwOjA0OjU4LjE3NjY3OVoiLCJpYXQiOiIyMDIxLTExLTE4VDIwOjAzOjE4LjE3NjY3OVoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.c7phh6GC0hqaPoBKWKtdyJqMcE3G3v+SXZuygevFIhqkB7do3YhSFWYfJ60DwyX5Bu10+DpWt11vUb+u3yGtCQ:oidP1H5ys88FQkxuhdlL5HVoCg9RdxodA6aD3RxlwaDHVf+iI1+HKKk9kFL6//kaAgTze9wQVrNJG1iQKFtUBQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2021-11-18T20:03:18.176028Z"), envelope.getClaim(Claim.IAT));
            assertEquals("Di:ME", envelope.getClaim(Claim.CTX));
            assertEquals(1, envelope.getItems().size());
            assertEquals(Message.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void exportTest1() {
        try {
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            envelope1.addItem(Commons.getIssuerIdentity());
            envelope1.addItem(Commons.getIssuerKey().publicCopy());
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();

            Envelope envelope2 = Envelope.importFromEncoded(exported);
            envelope2.verify(Commons.getIssuerKey());
            assertEquals(2, envelope2.getItems().size());

            Identity identity = (Identity)envelope2.getItems().get(0);
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), identity.getClaim(Claim.SUB));
            Key key = (Key)envelope2.getItems().get(1);
            assertEquals((UUID) Commons.getIssuerKey().getClaim(Claim.UID), key.getClaim(Claim.UID));
            assertNull(key.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

}
