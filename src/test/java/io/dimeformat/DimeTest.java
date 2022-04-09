//
//  DimeTest.java
//  Di:ME - Data Identity Message Envelope
//  Compact data format for trusted and secure communication between networked entities.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

public class DimeTest {

    @BeforeAll
    static void beforeAll() {
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

}
