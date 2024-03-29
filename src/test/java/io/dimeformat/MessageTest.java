//
//  MessageTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.CryptographyException;
import org.junit.jupiter.api.Test;
import io.dimeformat.exceptions.InvalidFormatException;
import io.dimeformat.enums.KeyCapability;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

class MessageTest {

    @Test
    void getHeaderTest1() {
        Message message = new Message();
        assertEquals("MSG", message.getHeader());
        assertEquals("MSG", Message.HEADER);
    }

    @Test
    void claimTest1() {
        Message message = new Message(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        assertNotNull(message.getClaim(Claim.ISS));
        assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), message.getClaim(Claim.ISS));
    }

    @Test
    void claimTest2() {
        Message message = new Message(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
        assertNotNull(message.getClaim(Claim.MIM));
        assertEquals(Commons.MIMETYPE, message.getClaim(Claim.MIM));
        message.removeClaim(Claim.MIM);
        assertNull(message.getClaim(Claim.MIM));
    }

    @Test
    void claimTest3() {
        try {
            Message message = new Message(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(message.getClaim(Claim.AMB));
            message.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(message.getClaim(Claim.AUD));
            message.putClaim(Claim.CMN, Commons.COMMON_NAME);
            assertNotNull(message.getClaim(Claim.CMN));
            message.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(message.getClaim(Claim.CTX));
            message.putClaim(Claim.EXP, Instant.now());
            assertNotNull(message.getClaim(Claim.EXP));
            message.putClaim(Claim.IAT, Instant.now());
            assertNotNull(message.getClaim(Claim.IAT));
            message.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(message.getClaim(Claim.ISS));
            message.putClaim(Claim.ISU, Commons.ISSUER_URL);
            assertNotNull(message.getClaim(Claim.ISU));
            message.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(message.getClaim(Claim.KID));
            message.putClaim(Claim.MIM, Commons.MIMETYPE);
            assertNotNull(message.getClaim(Claim.MIM));
            message.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(message.getClaim(Claim.MTD));
            message.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(message.getClaim(Claim.SUB));
            message.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(message.getClaim(Claim.SYS));
            message.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(message.getClaim(Claim.UID));
            try { message.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { message.putClaim(Claim.KEY, Commons.getIssuerKey().getSecret()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { message.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey(), Dime.crypto.getDefaultSuiteName())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { Map<String, Object> pri = new HashMap<>(); pri.put("tag", Commons.PAYLOAD); message.putClaim(Claim.PRI, pri); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { message.putClaim(Claim.PUB, Commons.getIssuerKey().getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            Message message = new Message(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            try { message.removeClaim(Claim.ISS); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { message.putClaim(Claim.EXP, Instant.now()); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest5() {
        try {
            Message message = new Message(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.strip();
            message.removeClaim(Claim.ISS);
            message.putClaim(Claim.IAT, Instant.now());
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void messageTest1() {
        Dime.setTimeModifier(0);
        Commons.initializeKeyRing();
        Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), 10);
        Instant now = Instant.now();
        assertEquals(0, Duration.between(message.getClaim(Claim.IAT), now).getSeconds());
        assertEquals(-10, Duration.between(message.getClaim(Claim.EXP), now).getSeconds());
        message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        assertNotNull(message.getClaim(Claim.UID));
        assertEquals((UUID) Commons.getAudienceIdentity().getClaim(Claim.SUB), message.getClaim(Claim.AUD));
        assertEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
    }

    @Test
    void messageTest2() {
        Commons.initializeKeyRing();
        byte[] payload = Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8);
        long validFor = 10;
        Message message1 = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), validFor);
        message1.setPayload(payload);
        Message message2 = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), validFor);
        message2.setPayload(payload);
        assertNotEquals((UUID) message1.getClaim(Claim.UID), message2.getClaim(Claim.UID));
    }

    @Test
    void messageTest3() {
        try {
            Commons.initializeKeyRing();
            String text = Commons.PAYLOAD;
            byte[] payload = text.getBytes(StandardCharsets.UTF_8);
            Message message1 = new Message(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            message1.setPayload(payload);
            assertNull(message1.getClaim(Claim.AUD));
            message1.sign(Commons.getIssuerKey());
            String exported = message1.exportToEncoded();
            Message message2 = Item.importFromEncoded(exported);
            assertNotNull(message2);
            assertNull(message2.getClaim(Claim.AUD));
            assertEquals(text, new String(message2.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void exportTest1() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), 10);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            String encoded = message.exportToEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
            assertTrue(encoded.startsWith(Commons.fullHeaderFor(Message.HEADER)));
            assertEquals(4, encoded.split("\\.").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }      
    }

    @Test
    void exportTest2() {
        Commons.initializeKeyRing();
        Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), 10);
        try {
            message.exportToEncoded();
        } catch (IllegalStateException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void exportTest3() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), 10);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            assertEquals(message.exportToEncoded(), message.exportToEncoded());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
    }

    @Test
    void verifyTest1() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), -10);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            assertFalse(message.verify(Commons.getIssuerKey()).isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest2() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Identity untrustedSender = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, key, Commons.SYSTEM_NAME, null);
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), untrustedSender.getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(key);
            assertFalse(message.verify(Commons.getIssuerKey()).isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest3() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerIdentity().getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest4() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB));
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerIdentity().getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest5() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB),1);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Thread.sleep(1000);
            assertFalse(message.verify(Commons.getIssuerIdentity().getPublicKey()).isValid(), "(This test may fail if run if the whole test suite is run in parallel)");
            Dime.setGracePeriod(1L);
            assertTrue(message.verify(Commons.getIssuerIdentity().getPublicKey()).isValid());
            Dime.setGracePeriod(0L);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }


    @Test
    void verifyTest6() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB),1);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Thread.sleep(2000);
            Dime.setTimeModifier(-2);
            assertTrue(message.verify(Commons.getIssuerIdentity().getPublicKey()).isValid(), "(This test may fail if run if the whole test suite is run in parallel)");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest7() {
        try {
            Dime.setTimeModifier(-2);
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), 1);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Thread.sleep(2000);
            assertFalse(message.verify(Commons.getIssuerIdentity().getPublicKey()).isValid(), "(This test may fail if run if the whole test suite is run in parallel)");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest1() { 
        try {
            Commons.initializeKeyRing();
            String exported = "Di:MSG.eyJ1aWQiOiIwY2VmMWQ4Zi01NGJlLTRjZTAtYTY2OS1jZDI4OTdhYzY0ZTAiLCJhdWQiOiJhNjkwMjE4NC0yYmEwLTRiYTAtYWI5MS1jYTc3ZGE3ZDA1ZDMiLCJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJleHAiOiIyMDIxLTExLTE4VDE4OjA2OjAyLjk3NDM5NVoiLCJpYXQiOiIyMDIxLTExLTE4VDE4OjA1OjUyLjk3NDM5NVoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.vWWk/1Ny6FzsVRNSEsqjhRrSEDvmbfLIE9CmADySp/pa3hqNau0tnhwH3YwRPPEpSl4wXpw0Uqkf56EQJI2TDQ";
            Message message = Item.importFromEncoded(exported);
            assertNotNull(message);
            assertEquals(UUID.fromString("0cef1d8f-54be-4ce0-a669-cd2897ac64e0"), message.getClaim(Claim.UID));
            assertEquals(UUID.fromString("a6902184-2ba0-4ba0-ab91-ca77da7d05d3"), message.getClaim(Claim.AUD));
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), message.getClaim(Claim.ISS));
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
            assertEquals(Instant.parse("2021-11-18T18:05:52.974395Z"), message.getClaim(Claim.IAT));
            assertEquals(Instant.parse("2021-11-18T18:06:02.974395Z"), message.getClaim(Claim.EXP));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest2() {
        Commons.initializeKeyRing();
        String encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
        try {
            Item.importFromEncoded(encoded);
            fail("Exception not thrown.");
        } catch (InvalidFormatException e) { /* all is well */ }
    }

    @Test
    void ImportTest3() {  
        try {
            Message message1 = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message1.sign(Commons.getIssuerKey());
            String encoded = message1.exportToEncoded();
            Message message2 = Item.importFromEncoded(encoded);
            assertNotNull(message2);
            message2.verify(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void signTest1() { 
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.sign(Commons.getIssuerKey());
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }
    
    @Test
    void signTest2() { 
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void signTest3() {
        // Multiple signatures
        try {
            Key key1 = Key.generateKey(KeyCapability.SIGN);
            Key key2 = Key.generateKey(KeyCapability.SIGN);
            Key key3 = Key.generateKey(KeyCapability.SIGN);
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(key1);
            assertTrue(message.verify(key1).isValid());
            message.sign(key2);
            assertTrue(message.verify(key1).isValid());
            assertTrue(message.verify(key2).isValid());
            assertFalse(message.verify(key3).isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSignedTest1() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            assertFalse(message.isSigned());
            message.sign(Commons.getIssuerKey());
            assertTrue(message.isSigned());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest1() {
        Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
        message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        assertEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
    }

    @Test
    void setPayloadTest2() {
        try {
            Message message1 = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            assertEquals(Commons.PAYLOAD, new String(message1.getPayload(), StandardCharsets.UTF_8));
            message1.sign(Commons.getIssuerKey());
            Message message2 = Item.importFromEncoded(message1.exportToEncoded());
            assertNotNull(message2);
            assertEquals(Commons.PAYLOAD, new String(message2.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest3() {
        try {
            Key localKey = Key.generateKey(KeyCapability.EXCHANGE);
            Key remoteKey = Key.generateKey(KeyCapability.EXCHANGE).publicCopy();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), localKey, remoteKey);
            assertNotEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest4() {
        try {
            Key issuerKey = Key.generateKey(KeyCapability.EXCHANGE);
            Key audienceKey = Key.generateKey(KeyCapability.EXCHANGE);
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.putClaim(Claim.KID, issuerKey.getClaim(Claim.UID));
            message.setPublicKey(audienceKey);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), audienceKey.publicCopy(), issuerKey);
            assertEquals((UUID) issuerKey.getClaim(Claim.UID), message.getClaim(Claim.KID));
            assertEquals(audienceKey.getPublic(), message.getPublicKey().getPublic());
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(audienceKey, issuerKey.publicCopy()), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest5() {
        try {
            Key issuerKey = Key.generateKey(KeyCapability.EXCHANGE);
            Key audienceKey = Key.generateKey(KeyCapability.EXCHANGE);
            Message message1 = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), issuerKey, audienceKey.publicCopy());
            message1.sign(Commons.getIssuerKey());
            Message message2 = Item.importFromEncoded(message1.exportToEncoded());
            assertNotNull(message2);
            String plainText = new String(message2.getPayload(issuerKey.publicCopy(), audienceKey), StandardCharsets.UTF_8);
            assertEquals(Commons.PAYLOAD, plainText);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest6() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), key, key);
        } catch (IllegalArgumentException e) {
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void setPayloadTest7() {
        try {
            Key key1 = Key.generateKey(KeyCapability.EXCHANGE);
            Message message = new Message();
            Key key2 = message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), key1.publicCopy());
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), key1.publicCopy(), key2);
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(key1), StandardCharsets.UTF_8));
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(key1, key2.publicCopy()), StandardCharsets.UTF_8));
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(key2.publicCopy(), key1), StandardCharsets.UTF_8));
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(key1.publicCopy(), key2), StandardCharsets.UTF_8));
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(key2, key1.publicCopy()), StandardCharsets.UTF_8));
            try { message.getPayload(key2); fail("Exception not thrown."); } catch (CryptographyException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest8() {
        try {
            Message message = new Message();
            Key keyExchange = Key.generateKey(KeyCapability.EXCHANGE);
            Key keySign = Key.generateKey(KeyCapability.SIGN);
            // setPayload
            try { message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), (Key) null); fail("Exception not thrown."); } catch (NullPointerException e) { /* all is well */ }
            try { message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), keyExchange); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), keySign); fail("Exception not thrown."); } catch (CryptographyException e) { /* all is well */ }
            // getPayload
            try { message.getPayload(null); fail("Exception not thrown."); } catch (NullPointerException e) { /* all is well */ }
            try { message.getPayload(keyExchange); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { message.getPayload(keySign); fail("Exception not thrown."); } catch (CryptographyException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest9() {
        try {
            Key key = Key.generateKey(KeyCapability.ENCRYPT);
            Message message = new Message();
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), key);
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(key), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void linkItemTest1() {
        try {
            Commons.initializeKeyRing();
            Identity issuer = Commons.getIssuerIdentity();
            Identity receiver = Commons.getAudienceIdentity();
            Message issuerMessage = new Message(receiver.getClaim(Claim.SUB), issuer.getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            issuerMessage.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            issuerMessage.sign(Commons.getIssuerKey());
            Message responseMessage = new Message(issuer.getClaim(Claim.SUB), receiver.getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            responseMessage.setPayload("It is!".getBytes(StandardCharsets.UTF_8));
            responseMessage.addItemLink(issuerMessage);
            responseMessage.sign(Commons.getAudienceKey());
            String responseEncoded = responseMessage.exportToEncoded();
            Message finalMessage = Item.importFromEncoded(responseEncoded);
            assertNotNull(finalMessage);
            finalMessage.verify(Commons.getAudienceKey(), List.of(issuerMessage));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void linkItemTest2() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.addItemLink(Key.generateKey(List.of(KeyCapability.EXCHANGE)));
            message.sign(Commons.getIssuerKey());
            assertFalse(message.verify(Commons.getIssuerKey(), List.of(Commons.getIssuerKey())).isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void linkItemTest3() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            try { message.addItemLink(Key.generateKey(List.of(KeyCapability.EXCHANGE))); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void linkItemTest4() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setItemLinks(List.of(Commons.getAudienceIdentity(), Commons.getIssuerIdentity()));
            assertEquals(2, message.getItemLinks().size());
            message.removeLinkItems();
            assertNull(message.getItemLinks());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest1() {
        try {
            Commons.initializeKeyRing();
            Message message1 = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message1.sign(Commons.getIssuerKey());
            String thumbprint1 = message1.generateThumbprint();
            String encoded = message1.exportToEncoded();
            Message message2 = Item.importFromEncoded(encoded);
            assertNotNull(message2);
            String thumbprint2 = message2.generateThumbprint();
            assertEquals(thumbprint1, thumbprint2);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest2() {
        try {
            Commons.initializeKeyRing();
            Identity issuer = Commons.getIssuerIdentity();
            Identity receiver = Commons.getAudienceIdentity();
            Message issuerMessage1 = new Message(receiver.getClaim(Claim.SUB), issuer.getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            issuerMessage1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            issuerMessage1.sign(Commons.getIssuerKey());
            Message issuerMessage2 = new Message(receiver.getClaim(Claim.SUB), issuer.getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            issuerMessage2.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            issuerMessage2.sign(Commons.getIssuerKey());
            assertNotEquals(issuerMessage1.generateThumbprint(), issuerMessage2.generateThumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Message message = new Message(null, Commons.getIssuerIdentity().getClaim(Claim.ISS), -1, context);
        assertEquals(context, message.getClaim(Claim.CTX));
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Message message1 = new Message(null, Commons.getIssuerIdentity().getClaim(Claim.ISS), -1, context);
            message1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message1.sign(Commons.getIssuerKey());
            String exported = message1.exportToEncoded();
            Message message2 = Item.importFromEncoded(exported);
            assertNotNull(message2);
            assertEquals(context, message2.getClaim(Claim.CTX));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Message(null, Commons.getIssuerIdentity().getClaim(Claim.ISS), -1, context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void stripTest1() {
        try {
            Message message = new Message(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            try {
                message.setPublicKey(Commons.getIssuerKey().publicCopy());
                fail("Expected exception was not thrown.");
            } catch (IllegalStateException e) {
                // All is good
            }
            message.strip();
            message.sign(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
