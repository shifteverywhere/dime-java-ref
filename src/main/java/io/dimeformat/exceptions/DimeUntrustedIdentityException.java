//
//  DimeUntrustedIdentityException.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

/**
 * Exception that is thrown if there is any problems with verifying the trust of
 * an identity.
 */
public class DimeUntrustedIdentityException extends Exception {

    /**
     * Create a new exception with a description.
     * @param message A short description of what happened.
     */
    public DimeUntrustedIdentityException(String message) {
        super(message);
    }
    
    /**
     * Create a new exception with a description and the underlying
     * causing exception.
     * @param message A short description of what happened.
     * @param cause The causing exception.
     */
    public DimeUntrustedIdentityException(String message, Exception cause) {
        super(message, cause);
    }

}
