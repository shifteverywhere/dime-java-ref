//
//  MessageTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.VerificationException;
import org.junit.jupiter.api.Test;
import io.dimeformat.exceptions.DimeDateException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeIntegrityException;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

class MessageTest {

    @Test
    void getItemIdentifierTest1() {
        Message message = new Message();
        assertEquals("MSG", message.getItemIdentifier());
        assertEquals("MSG", Message.ITEM_IDENTIFIER);
    }

    @Test
    void messageTest1() {
        Dime.setTimeModifier(0);
        Commons.initializeKeyRing();
        Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
        Instant now = Instant.now();
        assertEquals(0, Duration.between(message.getIssuedAt(), now).getSeconds());
        assertEquals(-10, Duration.between(message.getExpiresAt(), now).getSeconds());
        message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        assertNotNull(message.getUniqueId());
        assertEquals(Commons.getAudienceIdentity().getSubjectId(), message.getAudienceId());
        assertEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
    }

    @Test
    void messageTest2() {
        Commons.initializeKeyRing();
        byte[] payload = Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8);
        long validFor = 10;
        Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), validFor);
        message1.setPayload(payload);
        Message message2 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), validFor);
        message2.setPayload(payload);
        assertNotEquals(message1.getUniqueId(), message2.getUniqueId());
    }

    @Test
    void messageTest3() {
        try {
            Commons.initializeKeyRing();
            String text = Commons.PAYLOAD;
            byte[] payload = text.getBytes(StandardCharsets.UTF_8);
            Message message1 = new Message(Commons.getIssuerIdentity().getSubjectId());
            message1.setPayload(payload);
            assertNull(message1.getAudienceId());
            message1.sign(Commons.getIssuerKey());
            String exported = message1.exportToEncoded();
            Message message2 = Item.importFromEncoded(exported);
            assertNotNull(message2);
            assertNull(message2.getAudienceId());
            assertEquals(text, new String(message2.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void exportTest1() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            String encoded = message.exportToEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
            assertTrue(encoded.startsWith(Commons.fullHeaderFor(Message.ITEM_IDENTIFIER)));
            assertEquals(4, encoded.split("\\.").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }      
    }

    @Test
    void exportTest2() {
        Commons.initializeKeyRing();
        Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
        try {
            message.exportToEncoded();
        } catch (IllegalStateException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void exportTest3() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
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
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), -10);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerKey());
            fail("Exception not thrown.");
        } catch (VerificationException e) {
            /* all is well */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest2() {
        try {
            Key key = Key.generateKey(List.of(Key.Use.SIGN));
            Identity untrustedSender = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 120, key, Commons.SYSTEM_NAME, null);
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), untrustedSender.getSubjectId(), 120);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(key);
            message.verify(Commons.getIssuerKey());
            fail("Exception not thrown.");
        } catch (VerificationException e) {
           /* all is well */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest3() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 120);
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
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId());
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
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(),1);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Thread.sleep(1000);
            try {
                message.verify(Commons.getIssuerIdentity().getPublicKey());
                fail("Exception not thrown.");
            } catch (VerificationException e) { /* All is good */ }
            Dime.setGracePeriod(1L);
            message.verify(Commons.getIssuerIdentity().getPublicKey());
            Dime.setGracePeriod(0L);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    /*
    // This test is commented since it difficult to pass when build server is running all tests at the same time.
    @Test
    void verifyTest6() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(),1);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Thread.sleep(2000);
            Dime.setTimeModifier(-2);
            message.verify(Commons.getIssuerIdentity().getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }
    */

    @Test
    void verifyTest7() {
        try {
            Dime.setTimeModifier(-2);
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 1);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Thread.sleep(2000);
            message.verify(Commons.getIssuerIdentity().getPublicKey());
            fail("Exception not thrown.");
        } catch (VerificationException e) {
           /* all is good */
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
            assertEquals(UUID.fromString("0cef1d8f-54be-4ce0-a669-cd2897ac64e0"), message.getUniqueId());
            assertEquals(UUID.fromString("a6902184-2ba0-4ba0-ab91-ca77da7d05d3"), message.getAudienceId());
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), message.getIssuerId());
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
            assertEquals(Instant.parse("2021-11-18T18:05:52.974395Z"), message.getIssuedAt());
            assertEquals(Instant.parse("2021-11-18T18:06:02.974395Z"), message.getExpiresAt());
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
        } catch (DimeFormatException e) { /* all is well */ }
    }

    @Test
    void ImportTest3() {  
        try {
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 120);
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
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
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
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
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
            Key key1 = Key.generateKey(List.of(Key.Use.SIGN));
            Key key2 = Key.generateKey(List.of(Key.Use.SIGN));
            Key key3 = Key.generateKey(List.of(Key.Use.SIGN));
            Message message = new Message(Commons.getIssuerIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(key1);
            message.verify(key1);
            message.sign(key2);
            message.verify(key1);
            message.verify(key2);
            try {
                message.verify(key3);
                fail("Exception not thrown.");
            } catch (VerificationException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void isSignedTest1() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
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
        Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
        message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        assertEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
    }

    @Test
    void setPayloadTest2() {
        try {
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
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
            Key localKey = Key.generateKey(List.of(Key.Use.EXCHANGE));
            Key remoteKey = Key.generateKey(List.of(Key.Use.EXCHANGE)).publicCopy();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), localKey, remoteKey);
            assertNotEquals(Commons.PAYLOAD, new String(message.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest4() {
        try {
            Key issuerKey = Key.generateKey(List.of(Key.Use.EXCHANGE));
            Key audienceKey = Key.generateKey(List.of(Key.Use.EXCHANGE));
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setKeyId(issuerKey.getUniqueId());
            message.setPublicKey(audienceKey);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), audienceKey.publicCopy(), issuerKey);
            assertEquals(issuerKey.getUniqueId(), message.getKeyId());
            assertEquals(audienceKey.getPublic(), message.getPublicKey().getPublic());
            assertEquals(Commons.PAYLOAD, new String(message.getPayload(audienceKey, issuerKey.publicCopy()), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest5() {
        try {
            Key issuerKey = Key.generateKey(List.of(Key.Use.EXCHANGE));
            Key audienceKey = Key.generateKey(List.of(Key.Use.EXCHANGE));
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
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
            Key key = Key.generateKey(List.of(Key.Use.SIGN));
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), key, key);
        } catch (IllegalArgumentException e) {
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void linkItemTest1() {
        try {
            Commons.initializeKeyRing();
            Identity issuer = Commons.getIssuerIdentity();
            Identity receiver = Commons.getAudienceIdentity();
            Message issuerMessage = new Message(receiver.getSubjectId(), issuer.getSubjectId(), 100);
            issuerMessage.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            issuerMessage.sign(Commons.getIssuerKey());
            Message responseMessage = new Message(issuer.getSubjectId(), receiver.getSubjectId(), 100);
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
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.addItemLink(Key.generateKey(List.of(Key.Use.EXCHANGE)));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerKey(), List.of(Commons.getIssuerKey()));
        } catch (VerificationException e) {
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void linkItemTest3() {
        try {
            Commons.initializeKeyRing();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.addItemLink(Key.generateKey(List.of(Key.Use.EXCHANGE)));
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void thumbprintTest1() {
        try {
            Commons.initializeKeyRing();
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message1.sign(Commons.getIssuerKey());
            String thumbprint1 = message1.thumbprint();
            String encoded = message1.exportToEncoded();
            Message message2 = Item.importFromEncoded(encoded);
            assertNotNull(message2);
            String thumbprint2 = message2.thumbprint();
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
            Message issuerMessage1 = new Message(receiver.getSubjectId(), issuer.getSubjectId(), 100);
            issuerMessage1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            issuerMessage1.sign(Commons.getIssuerKey());
            Message issuerMessage2 = new Message(receiver.getSubjectId(), issuer.getSubjectId(), 100);
            issuerMessage2.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            issuerMessage2.sign(Commons.getIssuerKey());
            assertNotEquals(issuerMessage1.thumbprint(), issuerMessage2.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void thumbprintTest3() {
        try {
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.thumbprint();
        } catch (IllegalStateException e) {
            /* All is well */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Message message = new Message(null, Commons.getIssuerIdentity().getIssuerId(), -1, context);
        assertEquals(context, message.getContext());
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Message message1 = new Message(null, Commons.getIssuerIdentity().getIssuerId(), -1, context);
            message1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message1.sign(Commons.getIssuerKey());
            String exported = message1.exportToEncoded();
            Message message2 = Item.importFromEncoded(exported);
            assertNotNull(message2);
            assertEquals(context, message2.getContext());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Message(null, Commons.getIssuerIdentity().getIssuerId(), -1, context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void stripTest1() {
        try {
            Message message = new Message(Commons.getIssuerIdentity().getSubjectId());
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

    @Test
    void alienMessageEncryptionTest1() {
        try {
            String text = Commons.PAYLOAD;
            Key clientKey = Item.importFromEncoded("Di:KEY.eyJ1aWQiOiIzOWYxMzkzMC0yYTJhLTQzOWEtYjBkNC1lMzJkMzc4ZDgyYzciLCJwdWIiOiIyREJWdG5NWlVjb0dZdHd3dmtjYnZBSzZ0Um1zOUZwNGJ4dHBlcWdha041akRVYkxvOXdueWRCUG8iLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0LjQ0NDA0MVoiLCJrZXkiOiIyREJWdDhWOEF4UWR4UFZVRkJKOWdScFA1WDQzNnhMbVBrWW9RNzE1cTFRd2ZFVml1NFM3RExza20ifQ");
            Key serverKey = Item.importFromEncoded("Di:KEY.eyJ1aWQiOiJjY2U1ZDU1Yi01NDI4LTRhMDUtOTZmYi1jZmU4ZTE4YmM3NWIiLCJwdWIiOiIyREJWdG5NYTZrcjNWbWNOcXNMSmRQMW90ZGtUMXlIMTZlMjV0QlJiY3pNaDFlc3J3a2hqYTdaWlEiLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0Ljg0NjEyMVoiLCJrZXkiOiIyREJWdDhWOTV5N2lvb1A0bmRDajd6d3dqNW1MVExydVhaaGg0RTJuMUE0SHoxQkIycHB5WXY1blIifQ");
            // This is received by the client //
            Message message = Item.importFromEncoded("Di:MSG.eyJpc3MiOiIzOTA3MWIyNC04MGRmLTQyYzEtYWQwZS1jNmQ2ZmNmMjg5YmIiLCJ1aWQiOiJjNjExOWYxMC0wZDE3LTQ3NTItYTkwZS1lODlhOGI2OGIyY2MiLCJpYXQiOiIyMDIyLTA2LTAzVDEzOjU0OjM2Ljg4MDM3MVoifQ.8sdEJ3CuHLaA/DmYcCce+8iflhQwESkDwIF8xu69R4h6Pvt+k6HfDJjK+sYm4goKoA04hb8Zaq9wMGiuxXoqqBHAGqd/.WorEis9t8WdQiOW+yK2F8gLfBfrnlFk/W7FMmjBhPWpp7SAddq2UPvE0nRo1TvWdqonhb2gm2TPMp0O0X4ULAQ");
            byte[] payload = message.getPayload(serverKey.publicCopy(), clientKey);
            assertEquals(text, new String(payload, StandardCharsets.UTF_8));
            // Client generate a response (to be sent to the server) //
            Message response = new Message(UUID.randomUUID());
            response.setPayload(text.getBytes(StandardCharsets.UTF_8), serverKey.publicCopy(), clientKey);
            response.sign(Key.generateKey(List.of(Key.Use.SIGN)));
            String exported = response.exportToEncoded();
            // This would really happen on the server side //
            Message received = Item.importFromEncoded(exported);
            byte[] payload2 = received.getPayload(serverKey, clientKey.publicCopy());
            assertEquals(text, new String(payload2, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void alienMessageEncryptionTest2() {
        try {
            Key clientLegacyKey = Item.importFromEncoded("Di:KEY.eyJ1aWQiOiI1MTllNWE5Mi01Yjc1LTQxMTctODZjMS1jMTFjZjI0MDY1YmUiLCJpYXQiOiIyMDIyLTA3LTAxVDA5OjEwOjEwLjc3MTQ2OFoiLCJwdWIiOiIyREJWdG5NYTFZM1B6a25FN3ZXTnJybkgyM0JVVlJROXVwRGM1Umd0MnloVFNEMUZoOFNiMXBhR3cifQ");
            Key serverKey = Item.importFromEncoded("Di:KEY.eyJpYXQiOiIyMDIyLTA3LTAxVDA4OjM2OjIwLjI2ODQ1M1oiLCJrZXkiOiJTVE4uOHZ2NWVKc2Q3dXVZUjlqNUhlbndCZ3Y3ZVVmWldpOVE3U2l4RHNYVVpobWp0azl6VyIsInB1YiI6IlNUTi4yTWZrcjhqTExHeGtMN2NQaUtiZGM4U3JqZTdnSDE4dmpzbUdaRXBlQlNaSkZiNlA2ZCIsInVpZCI6IjllOTMzMTRjLTZmMDAtNDFjMC1iNDEwLWQyOGI1YjNiOWU1ZSIsInVzZSI6WyJleGNoYW5nZSJdfQ");
            Message legacyMessage = Item.importFromEncoded("Di:MSG.eyJ1aWQiOiJiOTMxOWNiZS0xNzAzLTQ4MTQtYjQ2OC0wMzdmODJmYjNlNDAiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIyLTA3LTAxVDA5OjEwOjEwLjc4MDAzN1oifQ.fS10Cu3KBf/J+cKw6guu6cCO+NBdjrTsJudXNjmgoC4TtX4+HsHY8vmUMYuTLPwKYAQ7dNSchz52l7edgESIuemW1yzA.9bzv07SHm2Hd89iyjjUYLCY3LbvD/+Jw5drKqWnpZNGZRgK2VwWKJTLM0ffQcrvm2P572RBJ5mWhpPnZxLoPCA");
            assertNotNull(legacyMessage);
            assertEquals(Commons.PAYLOAD, new String(legacyMessage.getPayload(clientLegacyKey, serverKey), StandardCharsets.UTF_8));
            Identity clientLegacyIdentity = Item.importFromEncoded("Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiIyYzZmYTYwMS1mOWIyLTQxNGQtOThhNy00YWY5MDVkY2U1NzIiLCJzdWIiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJleHAiOiIyMDIyLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJwdWIiOiIyVERYZG9OdU1GaThqd0MzRE43WDJacW1aa0ZmNWE3cWV0elhUV0Fmbmt5aDZncnFZUHE5NE5lbm4iLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.pdZhvANop6iCyBvAmWqUFnviqTZRlw/mF4fjLj4MdbVRdsJDF8eOUYQJk+HoqAXE4i9NV18uAioVkKR1LM1WDw");
            assertNotNull(clientLegacyIdentity);
            legacyMessage.verify(clientLegacyIdentity.getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void alienMessageEncodingTest1() {
        try {
            // UUID are capital letters in alien message (encoding should be respected)
            String alienEncoded = "Di:MSG.eyJpc3MiOiI1MWRjN2QwMS04N2RjLTQ0YzUtOWQyNy0wZWYyNmQyN2I4NWYiLCJ1aWQiOiJmODBlNDgxMC01Yzk2LTQzMTItYjhhMC02ZWU5YTIzNzFkOTEiLCJhdWQiOiJiYjNkNjZkYy02YTI2LTQxY2EtODI1NS1iY2FiN2M1NTA3YTIiLCJleHAiOiIyMDIyLTA2LTIwVDAzOjI2OjQ0LjE1NDE1MTgwMFoiLCJpYXQiOiIyMDIyLTA2LTIwVDAzOjI0OjQ0LjE1NDE1MTgwMFoiLCJjdHgiOiJtZXNzYWdlLXJlcXVlc3QifQ.xUZbewSDMYyyD/cPi1d0E06pK5KsXKk2Pt3Cy/cR8UmeqXqBOiuyRb/S1r1oo7zTKRU60WpvyAOnzMOfQuXAulf+oT/l+Ts1ObFISzspVdoHQClHuZQkctB5W0H/DxFapfXMs8HiDvqa6jBtOL3pVzXvvZWSITKAIjlgPveJ5yXelLwnZH4OpF+Fuugulp5bGJcrr87jzERCvZMmyaFMCOPQnIxgY2pjNzAqfSE1yEHulijOpkxE5OQLsxvCYDaExlCJZ/aCsS12RKn0Xm6EKZzX0vjxtVjD60Z0/fQrO1smLMtyazegZ7CS5QWstU9z/95nPpxHHhNRATTXf/Ns3wW7swno6RVpXChg9+K82gDFeEeOklp0hoBvjBDYkFUF7mO1tVxHP0Ub+fB7bT+SRAvSUVtTMKZlcYmXBU4G0xA.qcp5mh4YvoMq/Hu7pPUgXXKBXZrlF0Akrkwon7HsTieHovEKu+apBpStLK6axlCZcvV2bd981Orw16ElS1Q9DA";
            Message alienMessage = Item.importFromEncoded(alienEncoded);
            assertNotNull(alienMessage);
            String localExported = alienMessage.exportToEncoded();
            assertEquals(alienEncoded, localExported);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
