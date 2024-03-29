//
//  InvalidFormatException.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

/**
 * Exception that is thrown if there is any problems when parsing Di:ME items or
 * envelopes.
 */
public class InvalidFormatException extends Exception {

    /**
     * Create a new exception with a description.
     * @param message A short description of what happened.
     */
    public InvalidFormatException(String message) {
        super(message);
    }

    /**
     * Create a new exception with a description and the underlying
     * causing exception.
     * @param message A short description of what happened.
     * @param exception The causing exception.
     */
    public InvalidFormatException(String message, Exception exception) {
        super(message, exception);
    }
}
