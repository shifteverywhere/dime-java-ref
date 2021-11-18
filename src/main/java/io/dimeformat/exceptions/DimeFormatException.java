//
//  DimeFormatException.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.exceptions;

public class DimeFormatException extends Exception {

    public DimeFormatException(String message) {
        super(message);
    }

    public DimeFormatException(String message, Exception exception) {
        super(message, exception);
    }
}
