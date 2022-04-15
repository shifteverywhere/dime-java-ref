//
//  DimeCapabilityException.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

/**
 * Exception that is thrown if there is any problems with capabilities for an identity.
 * This may happen when trying to issue a new identity and the identity issuing request (IIR)
 * contains more capabilities than allowed. It may also happen when an identity that is
 * missing the ISSUE capability is trying to issue a new identity from an IIR.
 */
public class DimeCapabilityException extends Exception {

    /**
     * Create a new exception with a description.
     * @param message A short description of what happened.
     */
    public DimeCapabilityException(String message) {
        super(message);
    }

}
