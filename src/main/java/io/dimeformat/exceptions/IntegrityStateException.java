//
//  IntegrityStateException.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

import io.dimeformat.keyring.IntegrityState;

/**
 * Exception that is thrown if there is any problems with verifying the integrity of an item. Is used in those cases
 * where it is not possible to return an instance of {@link io.dimeformat.keyring.IntegrityState}.
 */
public class IntegrityStateException extends Exception {

    /**
     * The integrity state fault that caused the exception.
     */
    public final IntegrityState state;

    /**
     * Create a new exception with the causing integrity state and exception message.
     * @param state The Integrity state that caused the exception.
     * @param message A short description of what happened.
     */
    public IntegrityStateException(IntegrityState state, String message) {
        super(message);
        this.state = state;
    }

}
