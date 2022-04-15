//
//  Capability.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.enums;

/**
 * Defines the capability or capabilities of an identity. This usually relates to what an identity may be used for.
 */
public enum Capability {

    /**
     * Capability set if the identity has been self-signed. This capability often indicates a root identity, the start
     * of a trust chain.
     */
    SELF,
    /**
     * A generic capability, may have been set after a simple registration. Depending on the application, the identity
     * may have limited usage.
     */
    GENERIC,
    /**
     * A capability that indicates that the identity have been verified and is associated with a higher level of
     * assurance. This may be done through more in-depth registration or secondary verification.
     */
    IDENTIFY,
    /**
     * This capability allows an identity to sign and issue other identities, thus creating leaf identities in a trust
     * chain. A root identity does often have this capability. However, it may be assigned to other identities further
     * down in a trust chain.
     */
    ISSUE

}
