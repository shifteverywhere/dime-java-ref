//
//  DimeCryptographicException.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

/**
 * Exception that is thrown if there is any problems with capabilities cryptographic 
 * operations. This may be when verifying signatures, generating keys or decryption data.
 */
public class DimeCryptographicException extends Exception {

    /**
     * Create a new exception with a description.
     * @param message A short description of what happened.
     */
    public DimeCryptographicException(String message) {
        super(message);
    }

}