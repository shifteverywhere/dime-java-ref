//
//  DimeDateException.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

/**
 * Exception that is thrown if there is any problems with dates stored inside a Di:ME. 
 * This may happen if an identity has expired, or if an issued at date is later than
 * an expired at date.
 */
public class DimeDateException extends Exception {

    /**
     * Create a new exception with a description.
     * @param message A short description of what happened.
     */
    public DimeDateException(String message) {
        super(message);
    }

}
