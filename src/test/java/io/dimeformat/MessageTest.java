//
//  MessageTest.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeKeyMismatchException;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.KeyType;
import io.dimeformat.exceptions.DimeDateException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeIntegrityException;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

class MessageTest {

    @Test
    void getTagTest1() {
        Message message = new Message(null, -1);
        assertEquals("MSG", message.getTag());
    }

    @Test
    void messageTest1() {
        Dime.setTimeModifier(0);
        Dime.setTrustedIdentity(Commons.getTrustedIdentity());
        Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
        Instant now = Instant.now();
        assertEquals(0, Duration.between(message.getIssuedAt(), now).getSeconds());
        assertEquals(-10, Duration.between(message.getExpiresAt(), now).getSeconds());
        message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
        assertNotNull(message.getUniqueId());
        assertEquals(Commons.getAudienceIdentity().getSubjectId(), message.getAudienceId());
        assertEquals("Racecar is racecar backwards.", new String(message.getPayload(), StandardCharsets.UTF_8));
    }

    @Test
    void messageTest2() {
        Dime.setTrustedIdentity(Commons.getTrustedIdentity());
        byte[] payload = "Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8);
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            String text = "Racecar is racecar backwards.";
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            String encoded = message.exportToEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
            assertTrue(encoded.startsWith(Envelope.HEADER + ":" + Message.TAG));
            assertEquals(4, encoded.split("\\.").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }      
    }

    @Test
    void exportTest2() {
        Dime.setTrustedIdentity(Commons.getTrustedIdentity());
        Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
        try {
            message.exportToEncoded();
        } catch (IllegalStateException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void exportTest3() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            assertEquals(message.exportToEncoded(), message.exportToEncoded());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
    }

    @Test
    void verifyTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), -10);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerKey());
        } catch (DimeDateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");    
    }

    @Test
    void verifyTest2() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY);
            Identity untrustedSender = IdentityIssuingRequest.generateIIR(key).selfIssueIdentity(UUID.randomUUID(), 120, key, Commons.SYSTEM_NAME, null);
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), untrustedSender.getSubjectId(), 120);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(key);
            message.verify(Commons.getIssuerKey());
        } catch (DimeIntegrityException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void verifyTest3() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 120);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerIdentity().getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest4() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId());
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerIdentity().getPublicKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest1() { 
        try {
            Identity.setTrustedIdentity(Commons.getTrustedIdentity());
            String exported = "Di:MSG.eyJ1aWQiOiIwY2VmMWQ4Zi01NGJlLTRjZTAtYTY2OS1jZDI4OTdhYzY0ZTAiLCJhdWQiOiJhNjkwMjE4NC0yYmEwLTRiYTAtYWI5MS1jYTc3ZGE3ZDA1ZDMiLCJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJleHAiOiIyMDIxLTExLTE4VDE4OjA2OjAyLjk3NDM5NVoiLCJpYXQiOiIyMDIxLTExLTE4VDE4OjA1OjUyLjk3NDM5NVoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.vWWk/1Ny6FzsVRNSEsqjhRrSEDvmbfLIE9CmADySp/pa3hqNau0tnhwH3YwRPPEpSl4wXpw0Uqkf56EQJI2TDQ";
            Message message = Item.importFromEncoded(exported);
            assertEquals(UUID.fromString("0cef1d8f-54be-4ce0-a669-cd2897ac64e0"), message.getUniqueId());
            assertEquals(UUID.fromString("a6902184-2ba0-4ba0-ab91-ca77da7d05d3"), message.getAudienceId());
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), message.getIssuerId());
            assertEquals("Racecar is racecar backwards.", new String(message.getPayload(), StandardCharsets.UTF_8));
            assertEquals(Instant.parse("2021-11-18T18:05:52.974395Z"), message.getIssuedAt());
            assertEquals(Instant.parse("2021-11-18T18:06:02.974395Z"), message.getExpiresAt());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest2() {  
        Dime.setTrustedIdentity(Commons.getTrustedIdentity());
        String encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
        try {
            Item.importFromEncoded(encoded);
        } catch (DimeFormatException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void ImportTest3() {  
        try {
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 120);
            message1.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void isSignedTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
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
        message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
        assertEquals("Racecar is racecar backwards.", new String(message.getPayload(), StandardCharsets.UTF_8));
    }

    @Test
    void setPayloadTest2() {
        try {
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message1.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            assertEquals("Racecar is racecar backwards.", new String(message1.getPayload(), StandardCharsets.UTF_8));
            message1.sign(Commons.getIssuerKey());
            Message message2 = Item.importFromEncoded(message1.exportToEncoded());
            assertNotNull(message2);
            assertEquals("Racecar is racecar backwards.", new String(message2.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest3() {
        try {
            Key localKey = Key.generateKey(KeyType.EXCHANGE);
            Key remoteKey = Key.generateKey(KeyType.EXCHANGE).publicCopy();
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8), localKey, remoteKey);
            assertNotEquals("Racecar is racecar backwards.", new String(message.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest4() {
        try {
            Key issuerKey = Key.generateKey(KeyType.EXCHANGE);
            Key audienceKey = Key.generateKey(KeyType.EXCHANGE);
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setKeyId(issuerKey.getUniqueId());
            message.setPublicKey(audienceKey);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8), audienceKey.publicCopy(), issuerKey);
            assertEquals(issuerKey.getUniqueId(), message.getKeyId());
            assertEquals(audienceKey.getPublic(), message.getPublicKey().getPublic());
            assertEquals("Racecar is racecar backwards.", new String(message.getPayload(audienceKey, issuerKey.publicCopy()), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest5() {
        try {
            Key issuerKey = Key.generateKey(KeyType.EXCHANGE);
            Key audienceKey = Key.generateKey(KeyType.EXCHANGE);
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message1.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8), issuerKey, audienceKey.publicCopy());
            message1.sign(Commons.getIssuerKey());
            Message message2 = Item.importFromEncoded(message1.exportToEncoded());
            assertNotNull(message2);
            String plainText = new String(message2.getPayload(issuerKey.publicCopy(), audienceKey), StandardCharsets.UTF_8);
            assertEquals("Racecar is racecar backwards.", plainText);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void setPayloadTest6() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY);
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8), key, key);
        } catch (DimeKeyMismatchException e) {
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void linkItemTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Identity issuer = Commons.getIssuerIdentity();
            Identity receiver = Commons.getAudienceIdentity();
            Message issuerMessage = new Message(receiver.getSubjectId(), issuer.getSubjectId(), 100);
            issuerMessage.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            issuerMessage.sign(Commons.getIssuerKey());
            Message responseMessage = new Message(issuer.getSubjectId(), receiver.getSubjectId(), 100);
            responseMessage.setPayload("It is!".getBytes(StandardCharsets.UTF_8));
            responseMessage.linkItem(issuerMessage);
            responseMessage.sign(Commons.getAudienceKey());
            String responseEncoded = responseMessage.exportToEncoded();
            Message finalMessage = Item.importFromEncoded(responseEncoded);
            assertNotNull(finalMessage);
            finalMessage.verify(Commons.getAudienceKey(), issuerMessage);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void linkItemTest2() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.linkItem(Key.generateKey(KeyType.EXCHANGE));
            message.sign(Commons.getIssuerKey());
            message.verify(Commons.getIssuerKey(), Commons.getIssuerKey());
        } catch (DimeIntegrityException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        fail("Should not happen.");
    }

    @Test
    void linkItemTest3() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            message.linkItem(Key.generateKey(KeyType.EXCHANGE));
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Message message1 = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message1.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
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
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Identity issuer = Commons.getIssuerIdentity();
            Identity receiver = Commons.getAudienceIdentity();
            Message issuerMessage1 = new Message(receiver.getSubjectId(), issuer.getSubjectId(), 100);
            issuerMessage1.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            issuerMessage1.sign(Commons.getIssuerKey());
            Message issuerMessage2 = new Message(receiver.getSubjectId(), issuer.getSubjectId(), 100);
            issuerMessage2.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            issuerMessage2.sign(Commons.getIssuerKey());
            assertNotEquals(issuerMessage1.thumbprint(), issuerMessage2.thumbprint());
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
            message1.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
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

}