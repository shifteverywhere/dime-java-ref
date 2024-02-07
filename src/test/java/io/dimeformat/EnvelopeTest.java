//
//  CryptoTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
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
            envelope.putClaim(Claim.CMN, Commons.COMMON_NAME);
            assertNotNull(envelope.getClaim(Claim.CMN));
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
            String exported = "Di.eyJpYXQiOiIyMDI0LTAxLTI2VDE1OjMxOjA3LjAxNTk3MDFaIiwiaXNzIjoiMzBiYjEwZGItY2QzNS00ZjNkLWIyNmEtYjdkZjBjNTgyNzljIn0:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjUtMDEtMjVUMTQ6NDY6MTUuNzk2NDQwMVoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjQ0MDFaIiwiaXNzIjoiMmYxZDBjNDItM2I4YS00N2E4LWIzN2QtMDkxN2I3NmI2NjM5IiwicHViIjoiTmFDbC5GSERJaC9RanBXSUV2dG5XVkFob0pBUWsreUdZZkdETFh6aGhpbDZQby9FIiwic3ViIjoiMzBiYjEwZGItY2QzNS00ZjNkLWIyNmEtYjdkZjBjNTgyNzljIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIxYjYyYmY0ZC05Yjk3LTQyOGMtYWJkNC04NzI1MGM1Y2MzNmMifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU9TMHdNUzB5TkZReE5EbzBOam94TlM0M09UVTJNelF5V2lJc0ltbGhkQ0k2SWpJd01qUXRNREV0TWpaVU1UUTZORFk2TVRVdU56azFOak0wTWxvaUxDSnBjM01pT2lJMk5UUTVPR1l4Tnkxak16STFMVFEzT1dNdFltWTVZeTA0TldFMFptSmxPR0V3WWpBaUxDSndkV0lpT2lKT1lVTnNMbXd5VEhGbGR6aGljbXBvYTBwSlFYVjZhbEIxYjB4SVV6TjVjR2RzTjFvcldVVkJiR1JEYTIxTUszTWlMQ0p6ZFdJaU9pSXlaakZrTUdNME1pMHpZamhoTFRRM1lUZ3RZak0zWkMwd09URTNZamMyWWpZMk16a2lMQ0p6ZVhNaU9pSnBieTVrYVcxbFptOXliV0YwTG5KbFppSXNJblZwWkNJNklqRXlPVEEwTUdJeExURTVPREF0TkRjeE1pMDRORGxsTFRrNE5UYzFNams1WkdKalpDSjkuTVdaaE9EWmxaV1F6WW1Fek5UY3pPQzVrTUdVeU1qZzBNMkprWkdNNVpUZ3dabVkyTXpVeFpHVm1OamczTTJGbU9HWmhZVEU0WVdReU1tVTBZMkkxWXpjMFlXWTJOakEzTXpsbE5HRXpObU5sTUdObU0yRm1ZalZrWVRRM1l6VXpaVGxtT0RsaFlXSTRNRGcxT1RZMFlqTTJOV0ZrTVdJNVpEVTRNbUkzWkRNeE1qWXhNbVJsTW1ReFpERm1NVEl3T1E.YzBlZWJhNGRiZTZhYjNjNy5mMWNlMzllNmZmOWM4NmUzNmU0Mzk2ZjkxNmMyYjcxMGJjNzY1MThjNTc2NmJiYjUwNzZmMGUxMGVlNTVjZjhhMGZlYWIxODgzZjM5NDYyZWMzMmU2ZTE0NDE4YWFhOWZmYjNjOTYzMDViMDdkN2FjMTk3ODQ4NjQ4ZjYxZDEwMQ:MWI0MDllMDVmYTYxNDQ3YS5kZGYwNjE1ZTBiMjc5ZTUzMGY3MjJlOTVlNzJjOTdjZDBhNWRmMmExMWRlMDZmM2E3ZDBhMWY3ZmY0MzliNmQ0NDNmYTZlOWRkMDA1ODZhOGFmNzYyZjE5ZGMyYWFkYTFiYTAyMTE2NmJiMjIyMWMxMWU0ZDMxY2M0NWQ3MTQwMw";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2024-01-26T15:31:07.0159701Z"), envelope.getClaim(Claim.IAT));
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
            String exported = "Di.eyJpYXQiOiIyMDI0LTAxLTI2VDE1OjMzOjE2LjkwNzEyNTVaIiwiaXNzIjoiMzBiYjEwZGItY2QzNS00ZjNkLWIyNmEtYjdkZjBjNTgyNzljIn0:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjQwMDNaIiwia2V5IjoiTmFDbC5oeHFXRXlTQ2VGV0VvYlFEQm9CNndOdGZvZGtrSDFnbU5uc0pvUDAzVk9BVWNNaUg5Q09sWWdTKzJkWlVDR2drQkNUN0laaDhZTXRmT0dHS1hvK2o4USIsInB1YiI6Ik5hQ2wuRkhESWgvUWpwV0lFdnRuV1ZBaG9KQVFrK3lHWWZHRExYemhoaWw2UG8vRSIsInVpZCI6ImY2OTQ2Njk2LTliYTItNDJiOS1hODIzLWJjZjcyZjZmYjg1NSJ9:MWI0MDllMDVmYTYxNDQ3YS43MjVjMWU5MTViODBjNmFiMzdlMjk0N2MwNjAxYTlmNmUzZmU0ODM3MDYyOThjNjg0MjIxYzgyODI4ZDY3OWQ4ZjQ4MDRkYjU3MDMwYzBmNWU1ZTM0ZWM2NjA5ZGJjOTE0N2ZiZTNlMThlYTBhZTA3NTUwYmUxYmUyZmUyMmQwNA";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2024-01-26T15:33:16.9071255Z"), envelope.getClaim(Claim.IAT));
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
            assertFalse(exported.isEmpty());
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void dataImportTest1() {
        try {
            String exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDI0LTAxLTI2VDE1OjI4OjQ4LjQ0MTQ2MjFaIiwiaXNzIjoiMzBiYjEwZGItY2QzNS00ZjNkLWIyNmEtYjdkZjBjNTgyNzljIn0:DAT.eyJleHAiOiIyMDI0LTAxLTI2VDE1OjI5OjQ4LjQ0MjE4MzRaIiwiaWF0IjoiMjAyNC0wMS0yNlQxNToyODo0OC40NDIxODM0WiIsImlzcyI6Ijk3N2I3NWU3LWJhZTAtNGJjMy05MTM2LWUzZGNjNGMxMDg5OSIsIm1pbSI6InRleHQvcGxhaW4iLCJ1aWQiOiIwZGNhZDEyNy0zMDdjLTQ5MjYtYmQxNi00ZDY4ZTA0OTllMzEifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.MWI0MDllMDVmYTYxNDQ3YS45NjIzYjcyNGVlNDBkNTliNGI0MmJjYmZmMzRiNDAxNWI1M2YyZTEzZTdlNGRmYmU4ZmI5ZWFkYjBkZDZkZDc2NTNjNzQzMDY1MWViMWIxMGE3NWVhNTY0NzZmMjE2MWExY2FlNzA5MDAyNzUzMDk4MzI4NjRlYTMwNWUwZTIwMg:MWI0MDllMDVmYTYxNDQ3YS40MjIyM2EzMzExZGQzZmJiODEyMjRkMGNkZjI4NjU0MzY5MWM1YTkzOTczZmI4ZjZjMmJkZmIzY2QxNmFkZjQ3NDlkOTFiMjIzNjE2OGIxZTQyODg3NjI0NmNhNzg1MDg3YjE0NWI5ZWY4M2UzNWI2NWM4NzFiYjRhYTI0MTcwYQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), envelope.getClaim(Claim.ISS));
            assertEquals(Instant.parse("2024-01-26T15:28:48.4414621Z"), envelope.getClaim(Claim.IAT));
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
            assertFalse(exported.isEmpty());
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
