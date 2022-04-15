//
//  DimeUntrustedIdentityException.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
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
