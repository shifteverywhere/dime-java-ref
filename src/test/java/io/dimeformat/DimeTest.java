//
//  DimeTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Capability;
import io.dimeformat.enums.KeyType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DimeTest {

    @BeforeAll
    static void beforeAll() {
        Dime.setTrustedIdentity(null);
        Dime.setTimeModifier(0);
        assertEquals(84, Dime.MAX_CONTEXT_LENGTH);
        assertNull(Dime.getTrustedIdentity());
        assertEquals(0, Dime.getTimeModifier());
    }

    @Test
    void trustedIdentityTest1() {
        Dime.setTrustedIdentity(null);
        assertNull(Dime.getTrustedIdentity());
        Dime.setTrustedIdentity(Commons.getTrustedIdentity());
        assertNotNull(Dime.getTrustedIdentity());
    }

    @Test
    void setTimeModifierTest1() {
        Dime.setTimeModifier(0);
        assertEquals(0, Dime.getTimeModifier());
        Dime.setTimeModifier(10);
        assertEquals(10, Dime.getTimeModifier());
    }

    @Test
    void createTimestampTest1() {
        Dime.setTimeModifier(0);
        Instant reference = Instant.now();
        Instant timestamp = Utility.createTimestamp();
        Duration duration = Duration.between(reference, timestamp);
        assertEquals(0, duration.getSeconds());
    }

    @Test
    void createTimestampTest2() {
        Instant reference = Instant.now();
        Dime.setTimeModifier(10);
        Instant timestamp = Utility.createTimestamp();
        Duration duration = Duration.between(reference, timestamp);
        assertEquals(10, duration.getSeconds());
    }

    @Test
    void createTimestampTest3() {
        Instant reference = Instant.now();
        Dime.setTimeModifier(-10);
        Instant timestamp = Utility.createTimestamp();
        Duration duration = Duration.between(reference, timestamp);
        assertEquals(-10, duration.getSeconds());
    }

    @Test
    void createTimestampTest4() {
        Instant reference = Instant.now().minusSeconds(2);
        Dime.setTimeModifier(-2);
        Instant timestamp = Utility.createTimestamp();
        Duration duration = Duration.between(reference, timestamp);
        assertEquals(0, duration.getSeconds());
    }

    @Test
    void gracefulTimestampCompareTest1() {
        int gracePeriod = 2;
        Instant now = Utility.createTimestamp();
        Instant remoteTimestamp1 = Instant.now().minusSeconds(2);
        int result = Utility.gracefulTimestampCompare(now, remoteTimestamp1, gracePeriod);
        assertEquals(0, result);
        Instant remoteTimestamp2 = Instant.now().plusSeconds(2);
        result = Utility.gracefulTimestampCompare(now, remoteTimestamp2, gracePeriod);
        assertEquals(0, result);
    }

    @Test
    void gracefulTimestampCompareTest2() {
        int gracePeriod = 1;
        Instant now = Utility.createTimestamp();
        Instant remoteTimestamp1 = Instant.now().minusSeconds(2);
        int result = Utility.gracefulTimestampCompare(Utility.createTimestamp(), remoteTimestamp1, gracePeriod);
        assertEquals(1, result);
        Instant remoteTimestamp2 = Instant.now().plusSeconds(2);
        result = Utility.gracefulTimestampCompare(now, remoteTimestamp2, gracePeriod);
        assertEquals(-1, result);
    }

    @Test
    void gracefulTimestampCompareTest3() {
        try {
            int gracePeriod = 2;
            Instant iat = Instant.parse("2022-01-01T23:43:34.8755323Z");
            Instant exp = Instant.parse("2022-01-01T23:43:32.8755323Z");
            Instant res = Instant.parse("2022-01-01T23:43:33.968000Z");
            Instant now = Instant.parse("2022-01-01T23:43:33.052000Z");
            assertTrue(Utility.gracefulTimestampCompare(iat, now, gracePeriod) <= 0); // checks so it passes
            assertTrue(Utility.gracefulTimestampCompare(res, now, gracePeriod) <= 0); // checks so it passes
            assertTrue(Utility.gracefulTimestampCompare(exp, now, gracePeriod) >= 0); // checks so it passes
            // Issued at and expires at are created by same entity and should not be compared with grace period
            assertTrue(Utility.gracefulTimestampCompare(iat, exp, 0) > 0); // check so it fails
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    // LEGACY TESTS //

    private static final String _legacyTrustedIdentity = "Di:ID.eyJ1aWQiOiI0MDViZDZhOC0wM2JmLTRjNDctOWNiYS0xNmNhODM5OGI1YzgiLCJzdWIiOiIxZmNkNWY4OC00YTc1LTQ3OTktYmQ0OC0yNWI2ZWEwNjQwNTMiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJpc3MiOiIxZmNkNWY4OC00YTc1LTQ3OTktYmQ0OC0yNWI2ZWEwNjQwNTMiLCJzeXMiOiJkaW1lLWphdmEtcmVmIiwiZXhwIjoiMjAzMS0xMS0xOFQxMjoxMTowMi43NjEwMDdaIiwicHViIjoiMlREWGRvTnZaUldoVUZYemVQam5nanlpbVlMUXNFWVl3ekV6ZDJlNjJqeHdGNHJkdTQzdml4bURKIiwiaWF0IjoiMjAyMS0xMS0yMFQxMjoxMTowMi43NjEwMDdaIn0.KE3hbTLB7+BzzEeGSFyauy2PMgXBIYpGqRFZ2n+xQQsAOxC45xYgeFvILtqLeVYKA8T5lcQvZdyuiHBPVMpxBw";
    public static final String _legacyIssuerIdentity = "Di:ID.eyJ1aWQiOiIyYTdkNDJhMy02YjQ1LTRhNGEtYmIzZC1lYzk0ZWMzNzlmMWYiLCJzdWIiOiJiZTRhZjVmMy1lODM4LTQ3MzItYTBmYy1mZmEyYzMyOGVhMTAiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImJkMjhkYjhmLTEzNjItNGFmZC1hZWQ3LTRjYTM5ZjY1OTc1ZSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTIwVDEyOjExOjAyLjc2NTI1OVoiLCJwdWIiOiIyVERYZG9OdzF3WlF0ZVU1MzI1czZSbVJYVnBUa1lXdlR1RXpSMWpOZFZ2WWpFUjZiNmJZYUR6dEYiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2NTI1OVoifQ.SUQuZXlKMWFXUWlPaUl5TTJRNVpXUmtaaTFtWXpoa0xUUmpNemN0WW1NNU1pMDNNVFF6TkRVMFlUSTBaRFVpTENKemRXSWlPaUppWkRJNFpHSTRaaTB4TXpZeUxUUmhabVF0WVdWa055MDBZMkV6T1dZMk5UazNOV1VpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pTVdaalpEVm1PRGd0TkdFM05TMDBOems1TFdKa05EZ3RNalZpTm1WaE1EWTBNRFV6SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UbFVNVEk2TVRFNk1ESXVOell6TmpVeVdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MlJEaGpRemwxZUZOaU5FcEdTSEpyTVdaUVNGZDNjWEZUUTFWS1IyVTRWbWRXUm5OaFZ6VkxjVVl5ZDJ0WVlsVlFUaUlzSW1saGRDSTZJakl3TWpFdE1URXRNakJVTVRJNk1URTZNREl1TnpZek5qVXlXaUo5LjU2djVMeVg4anRLQ3N0eTdnbTZOczJjWStiTUlYNHBxNDRnODBTRXB1NjF2QklzUlZ6UTFOZFY5Q1BXaHRTdHZEM3d3N01hOFg3QlZvMWxrMjZjMkRn.7H3RwTTeDcI3pGMIWMPbAjpDnCN2O91JG4lKu3JJbxlLNwTbgTB/03xrwi28wl0iMReJ4zUPc3cCqbymAlxwAw";

    @Test
    void legacyIdentityIssuingRequestImportTest1() {
        try {
            String exported = "Di:IIR.eyJ1aWQiOiIzZTViZGU0YS02Mjc3LTRkYTUtODY2NC0xZDNmMDQzYTkwMjgiLCJjYXAiOlsiZ2VuZXJpYyJdLCJwdWIiOiIyVERYZG9OdlNVTnlMRFNVaU1ocExDZEViRGF6NXp1bUQzNXRYMURBdUE4Q0U0MXhvREdnU2QzVUUiLCJpYXQiOiIyMDIxLTExLTE4VDEyOjAzOjUzLjM4MTY2MVoifQ.13/fVQLNOMbnHQXIE//T9PWnE0reDR0LVJUugy3SZ8J7g68idwutFqEGUiTwlPz/t0Ci1IU46kI+ftA83cc2AA";
            IdentityIssuingRequest iir = Item.importFromEncoded(exported);
            assertNotNull(iir);
            assertEquals(UUID.fromString("3e5bde4a-6277-4da5-8664-1d3f043a9028"), iir.getUniqueId());
            assertEquals(Instant.parse("2021-11-18T12:03:53.381661Z"), iir.getIssuedAt());
            assertTrue(iir.wantsCapability(Capability.GENERIC));
            assertEquals("2TDXdoNvSUNyLDSUiMhpLCdEbDaz5zumD35tX1DAuA8CE41xoDGgSd3UE", iir.getPublicKey().getPublic());
            iir.verify();
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void legacyIdentityImportTest1() {
        try {
            Dime.setTrustedIdentity(Item.importFromEncoded(DimeTest._legacyTrustedIdentity));
            String legacyExported = "Di:ID.eyJ1aWQiOiIyYTdkNDJhMy02YjQ1LTRhNGEtYmIzZC1lYzk0ZWMzNzlmMWYiLCJzdWIiOiJiZTRhZjVmMy1lODM4LTQ3MzItYTBmYy1mZmEyYzMyOGVhMTAiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImJkMjhkYjhmLTEzNjItNGFmZC1hZWQ3LTRjYTM5ZjY1OTc1ZSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTIwVDEyOjExOjAyLjc2NTI1OVoiLCJwdWIiOiIyVERYZG9OdzF3WlF0ZVU1MzI1czZSbVJYVnBUa1lXdlR1RXpSMWpOZFZ2WWpFUjZiNmJZYUR6dEYiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2NTI1OVoifQ.SUQuZXlKMWFXUWlPaUl5TTJRNVpXUmtaaTFtWXpoa0xUUmpNemN0WW1NNU1pMDNNVFF6TkRVMFlUSTBaRFVpTENKemRXSWlPaUppWkRJNFpHSTRaaTB4TXpZeUxUUmhabVF0WVdWa055MDBZMkV6T1dZMk5UazNOV1VpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pTVdaalpEVm1PRGd0TkdFM05TMDBOems1TFdKa05EZ3RNalZpTm1WaE1EWTBNRFV6SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UbFVNVEk2TVRFNk1ESXVOell6TmpVeVdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MlJEaGpRemwxZUZOaU5FcEdTSEpyTVdaUVNGZDNjWEZUUTFWS1IyVTRWbWRXUm5OaFZ6VkxjVVl5ZDJ0WVlsVlFUaUlzSW1saGRDSTZJakl3TWpFdE1URXRNakJVTVRJNk1URTZNREl1TnpZek5qVXlXaUo5LjU2djVMeVg4anRLQ3N0eTdnbTZOczJjWStiTUlYNHBxNDRnODBTRXB1NjF2QklzUlZ6UTFOZFY5Q1BXaHRTdHZEM3d3N01hOFg3QlZvMWxrMjZjMkRn.7H3RwTTeDcI3pGMIWMPbAjpDnCN2O91JG4lKu3JJbxlLNwTbgTB/03xrwi28wl0iMReJ4zUPc3cCqbymAlxwAw";
            Identity identity = Item.importFromEncoded(legacyExported);
            assertNotNull(identity);
            assertEquals(Commons.SYSTEM_NAME, identity.getSystemName());
            assertEquals(UUID.fromString("2a7d42a3-6b45-4a4a-bb3d-ec94ec379f1f"), identity.getUniqueId());
            assertEquals(UUID.fromString("be4af5f3-e838-4732-a0fc-ffa2c328ea10"), identity.getSubjectId());
            assertEquals(Instant.parse("2021-11-20T12:11:02.765259Z"), identity.getIssuedAt());
            assertEquals(Instant.parse("2022-11-20T12:11:02.765259Z"), identity.getExpiresAt());
            assertEquals(UUID.fromString("bd28db8f-1362-4afd-aed7-4ca39f65975e"), identity.getIssuerId());
            assertEquals("2TDXdoNw1wZQteU5325s6RmRXVpTkYWvTuEzR1jNdVvYjER6b6bYaDztF", identity.getPublicKey().getPublic());
            assertTrue(identity.hasCapability(Capability.GENERIC));
            assertTrue(identity.hasCapability(Capability.IDENTIFY));
            assertNotNull(identity.getTrustChain());
            assertTrue(identity.isTrusted());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void legacyKeyImport1() {
        try {
            String exported = "Di:KEY.eyJ1aWQiOiIzZjAwY2QxMy00NDc0LTRjMDQtOWI2Yi03MzgzZDQ5MGYxN2YiLCJwdWIiOiJTMjFUWlNMMXV2RjVtVFdLaW9tUUtOaG1rY1lQdzVYWjFWQmZiU1BxbXlxRzVHYU5DVUdCN1BqMTlXU2h1SnVMa2hSRUVKNGtMVGhlaHFSa2FkSkxTVEFrTDlEdHlobUx4R2ZuIiwiaWF0IjoiMjAyMS0xMS0xOFQwODo0ODoyNS4xMzc5MThaIiwia2V5IjoiUzIxVGtnb3p4aHprNXR0RmdIaGdleTZ0MTQxOVdDTVVVTTk4WmhuaVZBamZUNGluaVVrbmZVck5xZlBxZEx1YTJTdnhGZjhTWGtIUzFQVEJDcmRrWVhONnFURW03TXdhMkxSZCJ9";
            Key key = Item.importFromEncoded(exported);
            assertNotNull(key);
            assertEquals(KeyType.IDENTITY, key.getKeyType());
            assertEquals(UUID.fromString("3f00cd13-4474-4c04-9b6b-7383d490f17f"), key.getUniqueId());
            assertEquals(Instant.parse("2021-11-18T08:48:25.137918Z"), key.getIssuedAt());
            assertEquals("S21Tkgozxhzk5ttFgHhgey6t1419WCMUUM98ZhniVAjfT4iniUknfUrNqfPqdLua2SvxFf8SXkHS1PTBCrdkYXN6qTEm7Mwa2LRd", key.getSecret());
            assertEquals("S21TZSL1uvF5mTWKiomQKNhmkcYPw5XZ1VBfbSPqmyqG5GaNCUGB7Pj19WShuJuLkhREEJ4kLThehqRkadJLSTAkL9DtyhmLxGfn", key.getPublic());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void legacyMessageImport1() {
        try {
            String exported = "Di:MSG.eyJ1aWQiOiIwY2VmMWQ4Zi01NGJlLTRjZTAtYTY2OS1jZDI4OTdhYzY0ZTAiLCJhdWQiOiJhNjkwMjE4NC0yYmEwLTRiYTAtYWI5MS1jYTc3ZGE3ZDA1ZDMiLCJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJleHAiOiIyMDIxLTExLTE4VDE4OjA2OjAyLjk3NDM5NVoiLCJpYXQiOiIyMDIxLTExLTE4VDE4OjA1OjUyLjk3NDM5NVoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.vWWk/1Ny6FzsVRNSEsqjhRrSEDvmbfLIE9CmADySp/pa3hqNau0tnhwH3YwRPPEpSl4wXpw0Uqkf56EQJI2TDQ";
            Message message = Item.importFromEncoded(exported);
            assertNotNull(message);
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

}
