//
//  DimeTest.java
//  Di:ME - Data Identity Message Envelope
//  Compact data format for trusted and secure communication between networked entities.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.Instant;
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

}
