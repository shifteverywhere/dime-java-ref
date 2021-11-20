//
//  DimeDateException.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
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
