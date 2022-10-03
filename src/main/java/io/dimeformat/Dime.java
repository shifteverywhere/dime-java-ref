//
//  Dime.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.crypto.Crypto;
import io.dimeformat.crypto.KeyRing;

import java.time.Instant;


/**
 * Central class that handles a few important settings and constants.
 */
public final class Dime {

    /**
     * Manager of cryptographic suites and operations. May be used to add additional cryptographic suits in run-time.
     */
    public static final Crypto crypto = new Crypto();

    /**
     * A set of keys and identities that are set to be trusted.
     */
    public static final KeyRing keyRing = new KeyRing();

    /**
     * The maximum length that the context claim may hold.
     * */
    public static final int MAX_CONTEXT_LENGTH = 84;
    /**
     * The current version of the implemented Di:ME specification.
     */
    public static final int VERSION = 1;

    /**
     * A convenience constant for no expiration date.
     */
    public static final long NO_EXPIRATION = -1L;

    /**
     * A convenience constant holding the number of seconds for a minute.
     */
    public static final long VALID_FOR_1_MINUTE = 60L;

    /**
     * A convenience constant holding the number of seconds for an hour.
     */
    public static final long VALID_FOR_1_HOUR = VALID_FOR_1_MINUTE * 60L;

    /**
     * A convenience constant holding the number of seconds for a day.
     */
    public static final long VALID_FOR_1_DAY = VALID_FOR_1_HOUR * 24L;

    /**
     * A convenience constant holding the number of seconds for a year (based on 365 days).
     */
    public static final long VALID_FOR_1_YEAR = VALID_FOR_1_DAY * 365L;

    /**
     * Returns the currently set trusted identity. This is normally the root identity of a trust chain.
     * @return An Identity instance.
     */
    //public static synchronized Identity getTrustedIdentity() {
    //    return Dime.trustedIdentity;
    //}

    /**
     * Sets an Identity instance to be the trusted identity used for verifying a trust chain of other Identity
     * instances. This is normally the root identity of a trust chain.
     * @param trustedIdentity The Identity instance to set as a trusted identity.
     */
    //public static synchronized void setTrustedIdentity(Identity trustedIdentity) {
    //    Dime.trustedIdentity = trustedIdentity;
    //}

    /**
     * Returns the set grace period in seconds. This value is used to allow a grace period when comparing and validating
     * dates (issued at and expires at). A value of 2 will allow a grace margin of +/-2 seconds, given a total window of
     * 4 seconds.
     * @return The set grace period in seconds.
     */
    public static synchronized long getGracePeriod() {
        return Dime._gracePeriod;
    }

    /**
     * Sets the grace period, in seconds, that is used to allow for a grace period when comparing and validating dates
     * (issued at and expires at). A value of 2 will allow a grace margin of +/-2 seconds, given a total window of 4
     * seconds.
     * @param period The grace period to set, in seconds.
     */
    public static synchronized void setGracePeriod(long period) {
        if (period < 0) { throw new IllegalArgumentException("Unable to set grace period, must be a value of 0 or above."); }
        Dime._gracePeriod = period;
    }

    /**
     * Get the global time modifier. The modifier is in seconds. If none is set this will return 0.
     * @return The time modifier in use.
     */
    public static synchronized long getTimeModifier() { return Dime._timeModifier; }

    /**
     * Sets the global modifier, in seconds, for all captured timestamps. This may be used in clients with a calculated
     * time different from a server, or network base time. This may be either a positive, or negative number, setting 0
     * will turn time modification off. Generally it is more recommended that all entities in a network have synced
     * their local time with a common time-server. Servers, with multiple clients, should not use this.
     * @param modifier Number of seconds to modify timestamps with.
     */
    public static synchronized void setTimeModifier(long modifier) {
        Dime._timeModifier = modifier;
    }

    /**
     * This method will override the internal time with a provided time. This time is used to verify any timestamps and
     * overriding this should be used carefully and never in a production environment.
     * @param time The time to set.
     */
    public static synchronized void setOverrideTime(Instant time) {
        Dime._overrideTime = time;
    }

    /// PACKAGE-PRIVATE ///

    static final String COMPONENT_DELIMITER = ".";
    static final String SECTION_DELIMITER = ":";

    static Instant getTime() {

        if (Dime._overrideTime != null) {
            return _overrideTime;
        }
        return Instant.now();

    }

    /// PRIVATE ///

    //private static Identity trustedIdentity;
    private static long _gracePeriod = 0;
    private static long _timeModifier = 0;
    private static Instant _overrideTime = null;

    private Dime() {
        throw new IllegalStateException("Not intended to be instantiated.");
    }

}
