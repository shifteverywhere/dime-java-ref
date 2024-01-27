//
//  KeyTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.keyring.IntegrityState;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class KeyTest {

    @Test
    void getHeaderTest1() {
        Key key = new Key();
        assertEquals("KEY", key.getHeader());
        assertEquals("KEY", Key.HEADER);
    }

    @Test
    void claimTest1() {
        Key key = Key.generateKey(KeyCapability.SIGN);
        assertNull(key.getClaim(Claim.ISS));
        key.putClaim(Claim.ISS, Commons.getAudienceIdentity().getClaim(Claim.SUB));
        assertEquals((UUID) Commons.getAudienceIdentity().getClaim(Claim.SUB), key.getClaim(Claim.ISS));
    }

    @Test
    void claimTest2() {
        Key key = Key.generateKey(KeyCapability.SIGN);
        assertNotNull(key.getClaim(Claim.IAT));
        key.removeClaim(Claim.IAT);
        assertNull(key.getClaim(Claim.IAT));
    }

    @Test
    void claimTest3() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            key.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(key.getClaim(Claim.AMB));
            key.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.AUD));
            key.putClaim(Claim.CMN, Commons.COMMON_NAME);
            assertNotNull(key.getClaim(Claim.CMN));
            key.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(key.getClaim(Claim.CTX));
            key.putClaim(Claim.EXP, Instant.now());
            assertNotNull(key.getClaim(Claim.EXP));
            key.putClaim(Claim.IAT, Instant.now());
            assertNotNull(key.getClaim(Claim.IAT));
            key.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.ISS));
            key.putClaim(Claim.ISU, Commons.ISSUER_URL);
            assertNotNull(key.getClaim(Claim.ISU));
            key.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.KID));
            key.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(key.getClaim(Claim.MTD));
            key.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.SUB));
            key.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(key.getClaim(Claim.SYS));
            key.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.UID));
            try { key.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.KEY, key.getSecret()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey(), Dime.crypto.getDefaultSuiteName())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.MIM, Commons.MIMETYPE); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { Map<String, Object> pri = new HashMap<>(); pri.put("tag", Commons.PAYLOAD); key.putClaim(Claim.PRI, pri); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.PUB, key.getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            key.sign(Commons.getIssuerKey());
            try { key.removeClaim(Claim.IAT); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { key.putClaim(Claim.EXP, Instant.now()); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest5() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), Commons.CONTEXT);
            key.sign(Commons.getIssuerKey());
            key.strip();
            key.removeClaim(Claim.CTX);
            key.putClaim(Claim.IAT, Instant.now());
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void keyTest1() {
        Key key = Key.generateKey(KeyCapability.SIGN);
        assertEquals(1, key.getCapability().size());
        assertTrue(key.hasCapability(KeyCapability.SIGN));
        assertNotNull(key.getClaim(Claim.UID));
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyTest2() {
        Key key = Key.generateKey(KeyCapability.EXCHANGE);
        assertEquals(1, key.getCapability().size());
        assertTrue(key.hasCapability(KeyCapability.EXCHANGE));
        assertNotNull(key.getClaim(Claim.UID));
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyCapabilityTest1() {
        Key signKey = Key.generateKey(KeyCapability.SIGN);
        assertEquals(Dime.crypto.getDefaultSuiteName(), signKey.getCryptoSuiteName());
        assertNotNull(signKey.getSecret());
        assertNotNull(signKey.getPublic());
        List<KeyCapability> caps = signKey.getCapability();
        assertNotNull(caps);
        assertTrue(caps.contains(KeyCapability.SIGN));
        assertEquals(1, caps.size());
        assertTrue(signKey.hasCapability(KeyCapability.SIGN));
        assertFalse(signKey.hasCapability(KeyCapability.EXCHANGE));
        assertFalse(signKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyCapabilityTest2() {
        Key exchangeKey = Key.generateKey(KeyCapability.EXCHANGE);
        assertEquals(Dime.crypto.getDefaultSuiteName(), exchangeKey.getCryptoSuiteName());
        assertNotNull(exchangeKey.getSecret());
        assertNotNull(exchangeKey.getPublic());
        List<KeyCapability> caps = exchangeKey.getCapability();
        assertNotNull(caps);
        assertTrue(caps.contains(KeyCapability.EXCHANGE));
        assertEquals(1, caps.size());
        assertFalse(exchangeKey.hasCapability(KeyCapability.SIGN));
        assertTrue(exchangeKey.hasCapability(KeyCapability.EXCHANGE));
        assertFalse(exchangeKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyCapabilityTest3() {
        Key encryptionKey = Key.generateKey(KeyCapability.ENCRYPT);
        assertEquals(Dime.crypto.getDefaultSuiteName(), encryptionKey.getCryptoSuiteName());
        assertNotNull(encryptionKey.getSecret());
        assertNull(encryptionKey.getPublic());
        List<KeyCapability> caps = encryptionKey.getCapability();
        assertNotNull(caps);
        assertTrue(caps.contains(KeyCapability.ENCRYPT));
        assertEquals(1, caps.size());
        assertFalse(encryptionKey.hasCapability(KeyCapability.SIGN));
        assertFalse(encryptionKey.hasCapability(KeyCapability.EXCHANGE));
        assertTrue(encryptionKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyCapabilityTest4() {
        List<KeyCapability> caps = List.of(KeyCapability.SIGN, KeyCapability.EXCHANGE);
        try {
            Key.generateKey(caps, Dime.NO_EXPIRATION, null, null, Dime.crypto.getDefaultSuiteName());
            fail("Expected exception never thrown.");
        } catch (IllegalArgumentException ignored) { /* All is well good */ }
        catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void keyCapabilityTest5() {
        try {
            Key key1 = Key.generateKey(KeyCapability.SIGN);
            String exported1 = key1.exportToEncoded();
            Key key2 = Item.importFromEncoded(exported1);
            assertNotNull(key2);
            assertTrue(key2.hasCapability(KeyCapability.SIGN));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void exportTest1() {
        Key key = Key.generateKey(List.of(KeyCapability.SIGN));
        String exported = key.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.startsWith(Commons.fullHeaderFor(Key.HEADER)));
        assertEquals(2, exported.split("\\.").length);
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE1OjA5OjA5Ljk1NTYyNTVaIiwia2V5IjoiTmFDbC5PcDN3Yk0zaFNsdS93eXFFZkp2bDJhTHNBdGpQWmE4aVlYWUpvejhhY0pUUVoyTFkyZkhhL2VvQlVPRFhzaThzdFY1K1B4dHVYL29nTEh1ZUFQMDRrUSIsInB1YiI6Ik5hQ2wuMEdkaTJObngydjNxQVZEZzE3SXZMTFZlZmo4YmJsLzZJQ3g3bmdEOU9KRSIsInVpZCI6IjRiOTQxZWE0LTFjMmItNDBjZi1iYjMwLWIzZmE3N2ZkMDNhMCJ9";
            Key key = Item.importFromEncoded(exported);
            assertNotNull(key);
            assertEquals(1, key.getCapability().size());
            assertTrue(key.hasCapability(KeyCapability.SIGN));
            assertEquals(UUID.fromString("4b941ea4-1c2b-40cf-bb30-b3fa77fd03a0"), key.getClaim(Claim.UID));
            assertEquals(Instant.parse("2024-01-26T15:09:09.9556255Z"), key.getClaim(Claim.IAT));
            assertEquals("NaCl.Op3wbM3hSlu/wyqEfJvl2aLsAtjPZa8iYXYJoz8acJTQZ2LY2fHa/eoBUODXsi8stV5+PxtuX/ogLHueAP04kQ", key.getSecret());
            assertEquals("NaCl.0Gdi2Nnx2v3qAVDg17IvLLVefj8bbl/6ICx7ngD9OJE", key.getPublic());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void publicOnlyTest1() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), 120, UUID.randomUUID(), Commons.CONTEXT);
            assertNotNull(key.getSecret());
            Key pubOnly = key.publicCopy();
            assertNull(pubOnly.getSecret());
            assertEquals(key.getPublic(), pubOnly.getPublic());
            assertEquals((UUID) key.getClaim(Claim.UID), pubOnly.getClaim(Claim.UID));
            assertEquals((Instant)key.getClaim(Claim.IAT), pubOnly.getClaim(Claim.IAT));
            assertEquals((Instant) key.getClaim(Claim.EXP), pubOnly.getClaim(Claim.EXP));
            assertEquals((UUID) key.getClaim(Claim.ISS), pubOnly.getClaim(Claim.ISS));
            assertEquals((String) key.getClaim(Claim.CTX), pubOnly.getClaim(Claim.CTX));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void publicOnlyTest2() {
        try {
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Key pubOnly = Commons.getIssuerKey().publicCopy();
            message.verify(pubOnly);
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Key key = Key.generateKey(List.of(KeyCapability.SIGN), context);
        assertEquals(context, key.getClaim(Claim.CTX));
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key1 = Key.generateKey(List.of(KeyCapability.SIGN), context);
            String exported = key1.exportToEncoded();
            Key key2 = Item.importFromEncoded(exported);
            assertNotNull(key2);
            assertEquals(context, key2.getClaim(Claim.CTX));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try { Key.generateKey(List.of(KeyCapability.SIGN), context); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
    }

    @Test
    void stripTest1() {
        try {
            Key key = Key.generateKey(KeyCapability.ENCRYPT);
            key.sign(Commons.getIssuerKey());
            key.sign(Commons.getAudienceKey());
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getIssuerKey()));
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getAudienceKey()));
            assertTrue(key.strip(Commons.getAudienceKey()));
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getIssuerKey()));
            assertEquals(IntegrityState.FAILED_KEY_MISMATCH, key.verify(Commons.getAudienceKey()));
            assertFalse(key.strip(Commons.getAudienceKey()));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void commonNameTest1() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            key.putClaim(Claim.CMN, Commons.COMMON_NAME);
            assertEquals(key.getClaim(Claim.CMN), Commons.COMMON_NAME);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void commonNameTest2() {
        try {
            String exported = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjbW4iOiJEaU1FIiwiaWF0IjoiMjAyNC0wMS0yNlQxNzoyODowNi4xOTY0MzRaIiwia2V5IjoiTmFDbC5GVjNOM3crSXAxeHY3OHZ2L3JrWUJibzQyZElGVnZ6cTN3SGo1cUZTazVjcXpiTStrbEFuYTZjalV3bURpeVRyc2FJdWY2MmFHNWFuNFArd1FrV0h5QSIsInB1YiI6Ik5hQ2wuS3MyelBwSlFKMnVuSTFNSmc0c2s2N0dpTG4rdG1odVdwK0Qvc0VKRmg4ZyIsInVpZCI6ImZjZDNkMzI2LWY2NzQtNGQyZi1iODFhLTA3NWZlYmIwYTFkNSJ9";
            Key key = Item.importFromEncoded(exported);
            assertNotNull(key);
            assertNotNull(key.getClaim(Claim.CMN));
            assertEquals(Commons.COMMON_NAME, key.getClaim(Claim.CMN));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void nameTest1()
    {
        Key key1 = Key.generateKey(KeyCapability.SIGN);
        Key key2 = Key.generateKey(KeyCapability.SIGN);
        assertNotNull(key1.getName());
        assertNotNull(key2.getName());
        assertNotEquals(key1.getName(), key2.getName());
    }

}