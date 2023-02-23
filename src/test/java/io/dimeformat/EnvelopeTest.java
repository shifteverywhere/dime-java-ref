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
            envelope.putClaim(Claim.CNM, Commons.COMMON_NAME);
            assertNotNull(envelope.getClaim(Claim.CNM));
            envelope.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(envelope.getClaim(Claim.CTX));
            envelope.putClaim(Claim.EXP, Instant.now());
            assertNotNull(envelope.getClaim(Claim.EXP));
            envelope.putClaim(Claim.IAT, Instant.now());
            assertNotNull(envelope.getClaim(Claim.IAT));
            envelope.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(envelope.getClaim(Claim.ISS));
            envelope.putClaim(Claim.ISU, Commons.ISSUER_URL);
            assertNotNull(envelope.getClaim(Claim.ISU));
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
            try { envelope.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey(), Dime.crypto.getDefaultSuiteName())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
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
            Message message = new Message(UUID.randomUUID(), UUID.randomUUID(), Dime.NO_EXPIRATION, Commons.CONTEXT);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Envelope envelope = new Envelope();
            envelope.addItem(message);
            envelope.addItem(key);
  //          String encoded = envelope.exportToEncoded();
            // Context
            Item item1 = envelope.getItem(Claim.CTX, Commons.SIGN_KEY_CONTEXT);
            assertTrue(item1 instanceof Key);
            assertEquals(Commons.SIGN_KEY_CONTEXT, item1.getClaim(Claim.CTX));
            Item item2 = envelope.getItem(Claim.CTX, Commons.CONTEXT);
            assertTrue(item2 instanceof Message);
            assertEquals(Commons.CONTEXT, item2.getClaim(Claim.CTX));
            // Unique ID
            Item item3 = envelope.getItem(Claim.UID, (UUID) key.getClaim(Claim.UID));
            assertTrue(item3 instanceof Key);
            assertEquals((UUID) key.getClaim(Claim.UID), item3.getClaim(Claim.UID));
            Item item4 = envelope.getItem(Claim.UID, (UUID) message.getClaim(Claim.UID));
            assertTrue(item4 instanceof Message);
            assertEquals((UUID) message.getClaim(Claim.UID), item4.getClaim(Claim.UID));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void getItemTest2() {
        try {
            String exported = "Di:MSG.eyJhdWQiOiI1ZWQyZTE3YS0wMjhjLTRjMjgtOWI5ZC0zMTFhYjY4YTAxYzQiLCJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTEwLTI0VDA4OjI4OjQzLjcxNzc4M1oiLCJpc3MiOiJjNDI1OTIzYS0xMjYyLTQ3ZmYtYWMwZC1kNTc0YWU0OTA2MTQiLCJ1aWQiOiJiZmYyNWFjNC02OWU0LTRkYmYtYjhlZC0xZDJiMjdlYmQ0ZjUifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.YjkyMjMwYzBkNTY0YjU0NS5mMzUzMTZmMGU3NzI4NzFiYzQ3Y2M2YjMxYWRkZDcwZWJhMTQ2NGIyOWI4Yzg4ODAxNjM2ZjAzM2Q1MWQ1YWNlNzQ4NWJjODRmY2NiYjBlNjM3YWVkNTJmOGMzYjkxOTA5NWU2MTQzZTEyZGVkOGZjOTYyZWVjZDAzZDRiYTkwYQ:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTI0VDA4OjI4OjQ4LjYyOTA4N1oiLCJrZXkiOiJTVE4uSzZzcU5kV3Bhd05GVmdGQ2ZjU1hHRWtjNTUxamJkYllQYXZyUk1LUUUyNVhFUEhMaThqcEYxeG5yRVR5TkJXZ0RzUnZoeHJjeTg1eVRmSG52Snl5OHZ4amV5RE05IiwicHViIjoiU1ROLm1McUVicWVEWlpQVWZ6QUpyZERyaVRKa3pyTTVBS2lveGtnTkJQazdpeGVIRGJ6cGMiLCJ1aWQiOiI0ZmU4ZjVjNi01OWQyLTQ3NjMtYjMxZC04MjU5YjUzMWFjMDgifQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            // Context
            Item item1 = envelope.getItem(Claim.CTX, Commons.SIGN_KEY_CONTEXT);
            assertTrue(item1 instanceof Key);
            assertEquals(Commons.SIGN_KEY_CONTEXT, item1.getClaim(Claim.CTX));
            Item item2 = envelope.getItem(Claim.CTX, Commons.CONTEXT);
            assertTrue(item2 instanceof Message);
            assertEquals(Commons.CONTEXT, item2.getClaim(Claim.CTX));
            // Unique ID
            UUID uid1 = UUID.fromString("4fe8f5c6-59d2-4763-b31d-8259b531ac08");
            Item item3 = envelope.getItem(Claim.UID, uid1);
            assertTrue(item3 instanceof Key);
            assertEquals(uid1, item3.getClaim(Claim.UID));
            UUID uid2 = UUID.fromString("bff25ac4-69e4-4dbf-b8ed-1d2b27ebd4f5");
            Item item4 = envelope.getItem(Claim.UID, uid2);
            assertTrue(item4 instanceof Message);
            assertEquals(uid2, item4.getClaim(Claim.UID));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void getItemTest3() {
        Envelope envelope = new Envelope();
        envelope.addItem(Key.generateKey(KeyCapability.SIGN));
        try { envelope.getItem(Claim.CTX, (String)null); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        assertNull(envelope.getItem(Claim.CTX,""));
        assertNull(envelope.getItem(Claim.CTX,"invalid-context"));
        try { envelope.getItem(Claim.UID, (UUID)null); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        assertNull(envelope.getItem(Claim.UID, UUID.randomUUID()));
    }

    @Test
    void getItemsTest1() {
        Envelope envelope = new Envelope();
        Key key1 = Key.generateKey(List.of(KeyCapability.SIGN), Commons.CONTEXT);
        key1.setClaimValue(Claim.ISS, Commons.getIssuerIdentity().getClaim(Claim.SUB));
        Key key2 = Key.generateKey(List.of(KeyCapability.EXCHANGE), Commons.CONTEXT);
        key2.setClaimValue(Claim.ISS, Commons.getIssuerIdentity().getClaim(Claim.SUB));
        Key key3 = Key.generateKey(List.of(KeyCapability.ENCRYPT), Commons.CONTEXT);
        key3.setClaimValue(Claim.ISS, Commons.getAudienceIdentity().getClaim(Claim.SUB));
        envelope.setItems(List.of(key1, key2, key3));
        assertSame(3, envelope.getItems(Claim.CTX, Commons.CONTEXT).size());
        assertSame(2, envelope.getItems(Claim.ISS, Commons.getIssuerIdentity().getClaim(Claim.SUB)).size());
        assertSame(1, envelope.getItems(Claim.ISS, Commons.getAudienceIdentity().getClaim(Claim.SUB)).size());
        assertSame(1, envelope.getItems(Claim.UID, key2.getClaim(Claim.UID)).size());
        assertSame(0, envelope.getItems(Claim.UID, UUID.randomUUID()).size());
        try { envelope.getItems(Claim.UID, (UUID)null); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
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
            assertNotNull(envelope.generateThumbprint());
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
            assertNotNull(envelope.generateThumbprint());
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
            assertEquals(envelope1.generateThumbprint(), envelope2.generateThumbprint());
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
            assertEquals(envelope1.generateThumbprint(), envelope2.generateThumbprint());
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
            assertEquals(envelope.generateThumbprint(), Envelope.thumbprint(exported));
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
            assertEquals(envelope.generateThumbprint(), Envelope.thumbprint(exported));
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
            String exported = "Di.eyJpYXQiOiIyMDIyLTEwLTI0VDIyOjEyOjIzLjE4ODYwNVoiLCJpc3MiOiI1NzE4OTg0MC0yMGFhLTRlZWEtOTg3OC1iOTIzYTc3ZmIyZWIifQ:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMjRUMjI6MDQ6MDkuMDQ1MjIxWiIsImlhdCI6IjIwMjItMTAtMjRUMjI6MDQ6MDkuMDQ1MjIxWiIsImlzcyI6IjBlY2JlYjFiLTcwYjQtNDRlYi1iYTUxLTlkYTVhOTZkOTM3YyIsInB1YiI6IkRTQy4zbm56Ri9PVkxXVnVoc3BLMmM2UVdrdHRLNEg2Q1hBWCszdHA5U0puUE9ZIiwic3ViIjoiNTcxODk4NDAtMjBhYS00ZWVhLTk4NzgtYjkyM2E3N2ZiMmViIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIyMGYwMmFlZi1lM2JiLTQwNTctOTA5OC0zZDg5M2U0ZjI0ZDQifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB5TTFReU1qb3dORG93T1M0d05ERTRPRFZhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB5TkZReU1qb3dORG93T1M0d05ERTRPRFZhSWl3aWFYTnpJam9pTVRjelpqVXlaRFl0TWpZM1l5MDBPRGsxTFRnME56TXRNakUzTURFMk1HWXpPRFpqSWl3aWNIVmlJam9pUkZORExsZzBWeTlWZGxOTU1VZHhWRmtyWmtGb00weEdZMFJIU3preWVuTlFNbTlKV1hoQmJGaE1iWFJxVUdzaUxDSnpkV0lpT2lJd1pXTmlaV0l4WWkwM01HSTBMVFEwWldJdFltRTFNUzA1WkdFMVlUazJaRGt6TjJNaUxDSnplWE1pT2lKcGJ5NWthVzFsWm05eWJXRjBMbkpsWmlJc0luVnBaQ0k2SW1VME0yUXpOV0l3TFdSaFpEWXROR015TWkwNU1HSXhMVEprTm1aaFlqa3haVGxpWlNKOS5NekprTVRRell6SmtNRFl5TXpBMllpNW1PVEkzTnpreE5tTTBZak15TW1NNU1UUTFNalV5WWpKaE9HRTJNREZoT1dKaVl6aGxNVGN4TVdJM01EQXpaamMwWTJJNE5qVTFNMlkwWVdVek56QXdZek5tWWpnMU9EWXdZakl4TkdJMlpEaGpaalUzWmpVMk16aGhPVGhqTUdKaFlqQXpPVFpoTWpGbE1EQTFNak5rTVdZMk1EVXhaVGhoT1dJeE5UUXdZZw.NTAyZmE0Y2Q1MWFiNTZkMi40MGZjZGRlYTZlNWVlMGNlMjc1Mjk2MmFjYzFkZGNlYjg3OGQxMWIzN2YxMjIzODY2MjRjNTFhNTJmYmRhYTZiMzYyYjQ2MjlmYmUyNDdkYzJjMGRlZGY0ZGM0OGVmNGE5NzdhNTE0MGU1YjFkZGFiNWJiZjU2Mzg4MjRkNzQwZA:NTE4OTRjZjc0YTNjZDZlMy4yOTk1ODRjN2FjNjlkM2MyODc2OGY1OTg0ODkyN2Q0MDM3N2Y3NzU2MmM3ZmJmYWMwNDE5NTA4YWViYTYzZTU0NGE5NjhjMDhiYTgzOWFlMmNiMWFkNTgxMzMxMTM0MjllZTQ4YjdmNmFhZDc0YmUzYTlmZTkxZjA0Y2UzZTkwNQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2022-10-24T22:12:23.188605Z"), envelope.getClaim(Claim.IAT));
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
            String exported = "Di.eyJpYXQiOiIyMDIyLTEwLTI0VDIyOjEzOjUyLjYxMjI3OFoiLCJpc3MiOiI1NzE4OTg0MC0yMGFhLTRlZWEtOTg3OC1iOTIzYTc3ZmIyZWIifQ:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA0OjA5LjA0NDc4N1oiLCJrZXkiOiJEU0MubXZ2c0pUN0ptNzJ6Uk1MSDdsdnpvdUdaS1NHNzFQbTZGUEI1bVVOejJwL2VlZk1YODVVdFpXNkd5a3JaenBCYVMyMHJnZm9KY0JmN2UybjFJbWM4NWciLCJwdWIiOiJEU0MuM25uekYvT1ZMV1Z1aHNwSzJjNlFXa3R0SzRINkNYQVgrM3RwOVNKblBPWSIsInVpZCI6ImJkMTkzYzJlLTIwOGQtNDJkYi1hZTFjLTYwYWQzYjE2MmI0MyJ9:NTE4OTRjZjc0YTNjZDZlMy42ZmY2ZmMzYWI3ODczNTJmYzI2YjE5MzM0MzgxOTNlNTFhNzEzYjc1YjBlMzVkMTYxZDgzNWRkOGFkNTU3MmM0ZWMyM2VkZGRhOTVlNWE3YjlmNmY0YzJkNTFhZTA0YWRlZjZlYzg3OGY2ZDcxZWI4Y2E5MzJhNjdlMGMwZjAwOQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2022-10-24T22:13:52.612278Z"), envelope.getClaim(Claim.IAT));
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
            Data data = new Data(Commons.getAudienceIdentity().getClaim(Claim.SUB),Dime.VALID_FOR_1_MINUTE);
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
            String exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjE0OjMwLjQ1NzAwMloiLCJpc3MiOiI1NzE4OTg0MC0yMGFhLTRlZWEtOTg3OC1iOTIzYTc3ZmIyZWIifQ:DAT.eyJleHAiOiIyMDIyLTEwLTI0VDIyOjE1OjMwLjQ1ODc5MFoiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjE0OjMwLjQ1ODc5MFoiLCJpc3MiOiIxYTk2Nzg3ZC1hZWYzLTQyYTgtOGM2Ny0xZjc5OTkzNDZjYmYiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiNWI0NGU1ZTgtOWI5NC00NDMxLTk3NTAtMDVmMDdkM2JiMmU5In0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.NTE4OTRjZjc0YTNjZDZlMy4yYjdiOWRkMzk5Zjc0MGMzOTFmNjYzNTdmYTcxMjc4M2I3Yzg4NjFmZTY1YTU0YTA2MTRjYWY4NzAwYjQ5NDFlNDk4ZTE1MjA1M2VlMTlhNmQ2OGEyMWFhY2Q2ZDE0N2VhOGIwYmIxZTEwMDEzODlkYzFmODAxMjVkMmQ5ZjkwNg:NTE4OTRjZjc0YTNjZDZlMy45MDE4NmI4YmIwN2VjZmMwN2VhNmJlYjk4NDFiZTY2YzAxYWZhNjdmYzI5OGNmZDk3ZDFlMWIxYjVhODhkY2VhYTQzODc5NDZiODhiNzkyNmI2MThjOGYyM2RjY2E0OWEyNmJhZTI2Y2I5NDVlNjUxMGQ2N2NhOTI0MGQ0OWUwNg";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2022-10-24T22:14:30.457002Z"), envelope.getClaim(Claim.IAT));
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
