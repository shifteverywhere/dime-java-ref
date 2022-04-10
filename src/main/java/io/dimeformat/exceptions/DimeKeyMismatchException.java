//
//  DimeKeyMismatchException.java
//  Di:ME - Data Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

/**
 * Exception that is thrown if there is any mismatch between keys provided to a 
 * method. This may happen when using a key of the wrong type.
 */
public class DimeKeyMismatchException extends  Exception {
    
    /**
     * Create a new exception with a description.
     * @param message A short description of what happened.
     */
    public DimeKeyMismatchException(String message) {
        super(message);
    }
}
