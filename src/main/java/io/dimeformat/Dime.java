//
//  Dime.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.crypto.Crypto;
import io.dimeformat.crypto.CryptoSuiteStandard;
import io.dimeformat.crypto.ICryptoSuite;

/**
 * Central class that handles a few important settings and constants.
 */
public final class Dime {

    public static final Crypto crypto = new Crypto();
    static {
        ICryptoSuite impl = new CryptoSuiteStandard();
        Dime.crypto.registerCryptoSuite(impl, Dime.STANDARD_SUITE);
        Dime.crypto.registerCryptoSuite(impl, Dime.LEGACY_SUITE);
        Dime.crypto.setDefaultSuiteName(Dime.STANDARD_SUITE);
    }

    /**
     * The maximum length that the context claim may hold.
     * */
    public static final int MAX_CONTEXT_LENGTH = 84;
    /**
     * The current version of the implemented Di:ME specification.
     */
    public static final int VERSION = 0x01;

    /**
     * A constant holding the number of seconds for a year (based on 365 days).
     */
    public static final long VALID_FOR_1_YEAR = 365L * 24 * 60 * 60;

    /**
     * The name for any legacy Dime keys that was created before the introduction of cryptographic suites.
     * This is just used for internal use and should not be exported.
     */
    public static final String LEGACY_SUITE = "LEGACY";

    /**
     * The name of the standard cryptographic suites used for Dime keys.
     */
    public static final String STANDARD_SUITE = "DSTN";

    /**
     * Returns the currently set trusted identity. This is normally the root identity of a trust chain.
     * @return An Identity instance.
     */
    public static synchronized Identity getTrustedIdentity() {
        return Dime.trustedIdentity;
    }

    /**
     * Sets an Identity instance to be the trusted identity used for verifying a trust chain of other Identity
     * instances. This is normally the root identity of a trust chain.
     * @param trustedIdentity The Identity instance to set as a trusted identity.
     */
    public static synchronized void setTrustedIdentity(Identity trustedIdentity) {
        Dime.trustedIdentity = trustedIdentity;
    }

    /**
     * Get the global time modifier. The modifier is in seconds. If none is set this will return 0.
     * @return The time modifier in use.
     */
    public static synchronized long getTimeModifier() { return Dime.timeModifier; }

    /**
     * Sets the global modifier, in seconds, for all captured timestamps. This may be used in clients with a calculated
     * time different from a server, or network base time. This may be either a positive, or negative number, setting 0
     * will turn time modification off. Generally it is more recommended that all entities in a network have synced
     * their local time with a common time-server. Servers, with multiple clients, should not use this.
     * @param modifier Number of seconds to modify timestamps with.
     */
    public static synchronized void setTimeModifier(long modifier) {
        Dime.timeModifier = modifier;
    }

    /// PACKAGE-PRIVATE ///

    static final String COMPONENT_DELIMITER = ".";
    static final String SECTION_DELIMITER = ":";

    /// PRIVATE ///

    private static Identity trustedIdentity;
    private static long timeModifier = 0;

    private Dime() {
        throw new IllegalStateException("Not intended to be instantiated.");
    }

}
