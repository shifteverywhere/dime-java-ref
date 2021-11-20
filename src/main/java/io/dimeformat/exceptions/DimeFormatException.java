//
//  DimeFormatException.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

/**
 * Exception that is thrown if there is any problems when parsing Di:ME items or
 * envelopes.
 */
public class DimeFormatException extends Exception {

    /**
     * Create a new exception with a description.
     * @param message A short description of what happened.
     */
    public DimeFormatException(String message) {
        super(message);
    }

    /**
     * Create a new exception with a description and the underlying
     * causing exception.
     * @param message A short description of what happened.
     * @param exception The causing exception.
     */
    public DimeFormatException(String message, Exception exception) {
        super(message, exception);
    }
}
