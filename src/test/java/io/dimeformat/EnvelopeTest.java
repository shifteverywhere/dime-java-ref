//
//  CryptoTest.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;

import io.dimeformat.enums.KeyType;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class EnvelopeTest {

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
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
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
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId(), context);
        assertEquals(context, envelope.getContext());
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getSubjectId(), context);
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            envelope1.addItem(message);
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();
            Envelope envelope2 = Envelope.importFromEncoded(exported);
            assertEquals(context, envelope2.getContext());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Envelope(Commons.getIssuerIdentity().getSubjectId(), context);
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
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
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
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getSubjectId());
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
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
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
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
            Envelope envelope = new Envelope();
            envelope.addItem(iir);
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertTrue(exported.split("\\:").length == 2);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    public void iirImportTest1() {
        try {
            String exported = "Di:IIR.eyJ1aWQiOiIzOWY0NmZjZC02YmQxLTQwZWQtODg3ZS02ZTBhZGYyOTczNmQiLCJjYXAiOlsiZ2VuZXJpYyJdLCJwdWIiOiIyVERYZG9OdkpwcGFvYW9BQnAyRnJXM0dGVTl5QTJRSDVXN0JBb2NtZ29qcDc1ek0xRHIyeEczTUgiLCJpYXQiOiIyMDIxLTExLTE4VDE5OjMyOjE3LjI1OTY2OVoifQ.8C9TzVO+/35NZ0H5vsi7QX9CvkF3Vof3IpwRwRgmi1zAU0nDLm2RzEN/JOnU1arD3yGRfyDFNvSlfWgdDZicCg";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertTrue(envelope.isAnonymous());
            assertNull(envelope.getIssuerId());
            assertEquals(1, envelope.getItems().length);
            assertEquals(IdentityIssuingRequest.class, envelope.getItems()[0].getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerIdentity());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertTrue(exported.split("\\:").length == 3);
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
        assertTrue(exported.split("\\:").length == 2);
    }

    @Test
    void identityImportTest1() {
        try {
            String exported = "Di.eyJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJpYXQiOiIyMDIxLTExLTE4VDE5OjQ0OjUyLjc1MDAxMloifQ:ID.eyJ1aWQiOiI2YWU2OGE3MC0xN2Y2LTQ1MDQtOWFlMy1jNWJhOWUyZDQ4ZmIiLCJzdWIiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjY4ODgwZmYzLWZlOTQtNGZmMC05MTQ4LTAwYjk4MDgzODg3NyIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloifQ.SUQuZXlKMWFXUWlPaUk1TnpOak16VmhNQzB3WW1Vd0xUUmpOVEV0T0dNMFppMDFaalkzWm1Nd01EYzRNalFpTENKemRXSWlPaUkyT0RnNE1HWm1NeTFtWlRrMExUUm1aakF0T1RFME9DMHdNR0k1T0RBNE16ZzROemNpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWkRNNVpUQmlNREV0TVdabE9DMDBZalkyTFdJeU1EZ3RZbUV4TXpoaU5XVXpPR1F3SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UZFVNVFE2TkRnNk1UWXVOVGswTmpnNFdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MWRVaG5NblUyTW1aNlpFZDVOSGhHUkVKTGNHZGpUWGhPWWt0UVF6UmhTMjUwYmxSeVVYQkhiMmw1YWsxTlFVUlNaaUlzSW1saGRDSTZJakl3TWpFdE1URXRNVGhVTVRRNk5EZzZNVFl1TlRrME5qZzRXaUo5LkRZUVB1NlN0S2dpaTgwYm9FeCtucEhteGhyYW40cGZmMFZ4RTVlTmxPd09UaThTNDhRbGFBM29UTndvMVNKV0JxT09VRStWRnQrMVdENXBZQm5IT0Fn.yoSmBKB/YAWQ68gh//utH8G2szGr1VkRlyvR7kdY5Iy2fHtuL5ynA+0ZsehLv/fk6H8poA0yj/qNFIKLOohtAw:ZSEKjL0RtBSUDNhDUXSxt8zCdBX/M2Q2c2cJ22MKe59Mj3qWTMFG8nl+NagF5hx2uNL703DtIAl8OItSjNQcAQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2021-11-18T19:44:52.750012Z"), envelope.getIssuedAt());
            assertNull(envelope.getContext());
            assertEquals(1, envelope.getItems().length);
            assertEquals(Identity.class, envelope.getItems()[0].getClass());
            envelope.verify(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityImportTest2() {
        try {
            String exported = "Di:ID.eyJ1aWQiOiI2YWU2OGE3MC0xN2Y2LTQ1MDQtOWFlMy1jNWJhOWUyZDQ4ZmIiLCJzdWIiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjY4ODgwZmYzLWZlOTQtNGZmMC05MTQ4LTAwYjk4MDgzODg3NyIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloifQ.SUQuZXlKMWFXUWlPaUk1TnpOak16VmhNQzB3WW1Vd0xUUmpOVEV0T0dNMFppMDFaalkzWm1Nd01EYzRNalFpTENKemRXSWlPaUkyT0RnNE1HWm1NeTFtWlRrMExUUm1aakF0T1RFME9DMHdNR0k1T0RBNE16ZzROemNpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWkRNNVpUQmlNREV0TVdabE9DMDBZalkyTFdJeU1EZ3RZbUV4TXpoaU5XVXpPR1F3SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UZFVNVFE2TkRnNk1UWXVOVGswTmpnNFdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MWRVaG5NblUyTW1aNlpFZDVOSGhHUkVKTGNHZGpUWGhPWWt0UVF6UmhTMjUwYmxSeVVYQkhiMmw1YWsxTlFVUlNaaUlzSW1saGRDSTZJakl3TWpFdE1URXRNVGhVTVRRNk5EZzZNVFl1TlRrME5qZzRXaUo5LkRZUVB1NlN0S2dpaTgwYm9FeCtucEhteGhyYW40cGZmMFZ4RTVlTmxPd09UaThTNDhRbGFBM29UTndvMVNKV0JxT09VRStWRnQrMVdENXBZQm5IT0Fn.yoSmBKB/YAWQ68gh//utH8G2szGr1VkRlyvR7kdY5Iy2fHtuL5ynA+0ZsehLv/fk6H8poA0yj/qNFIKLOohtAw";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertTrue(envelope.isAnonymous());
            assertNull(envelope.getIssuerId());
            assertEquals(1, envelope.getItems().length);
            assertEquals(Identity.class, envelope.getItems()[0].getClass());
            try {
                envelope.verify(Commons.getIssuerKey());
            } catch (IllegalStateException e) { return; } // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
        fail("Should not happen.");
    }

    @Test
    void keyExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertTrue(exported.split("\\:").length == 3);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void keyImportTest1() {
        try {
            String exported = "Di.eyJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJpYXQiOiIyMDIxLTExLTE4VDE5OjU1OjQzLjY5Njk2MFoifQ:KEY.eyJ1aWQiOiI4ZjEyNDgzMS01NzBlLTQyMmUtYjNiMS00NzlhNzI3ZTY2ZGEiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg1NzI2M1oiLCJrZXkiOiJTMjFUWlNMS1B2MVhDajdNVGN6V3ZkQVRUU3M5ek4xc3VKNUFEWnlZaldFcnZBaG1WZEduUDYxYm1HRlVodUFmcUg0UkQ1eGdTTjZaY2RhR1prMno4aXhSRnJVU05ZQmhzQnZyIn0:eGmbvRS7gkk9UPN7n2CX4Su5XtdL3qEoRwOqvEixS4mAkr+6qbD3ss4d9+VAMT00OBRKUH61uCoC0FYWTr8VBA";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2021-11-18T19:55:43.696960Z"), envelope.getIssuedAt());
            assertNull(envelope.getContext());
            assertEquals(1, envelope.getItems().length);
            assertEquals(Key.class, envelope.getItems()[0].getClass());
            envelope.verify(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void messageExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId(), "Di:ME");
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            envelope.addItem(message);
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertTrue(exported.split("\\:").length == 3);
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
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2021-11-18T20:03:18.176028Z"), envelope.getIssuedAt());
            assertEquals("Di:ME", envelope.getContext());
            assertEquals(1, envelope.getItems().length);
            assertEquals(Message.class, envelope.getItems()[0].getClass());
            envelope.verify(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void exportTest1() {
        try {
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope1.addItem(Commons.getIssuerIdentity());
            envelope1.addItem(Commons.getIssuerKey().publicCopy());
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();

            Envelope envelope2 = Envelope.importFromEncoded(exported);
            envelope2.verify(Commons.getIssuerKey());
            assertEquals(2, envelope2.getItems().length);

            Identity identity = (Identity)envelope2.getItems()[0];
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), identity.getSubjectId());
            Key key = (Key)envelope2.getItems()[1];
            assertEquals(Commons.getIssuerKey().getUniqueId(), key.getUniqueId());
            assertNull(key.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

}
