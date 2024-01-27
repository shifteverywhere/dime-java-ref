//
//  MessageTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.KeyCapability;
import io.dimeformat.keyring.IntegrityState;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureTest {

    @Test
    void SignatureTest1() {
        try {
            Key key1 = Key.generateKey(KeyCapability.SIGN);
            Key key2 = Key.generateKey(KeyCapability.SIGN);
            Key key3 = Key.generateKey(KeyCapability.SIGN);
            Data data = new Data();
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            assertNull(data.getSignatures());
            data.sign(key1);
            data.sign(key2);
            assertNotNull(data.getSignatures());
            assertEquals(2, data.getSignatures().size());
            assertNotNull(Signature.find(key1.getName(), data.getSignatures()));
            assertEquals(IntegrityState.COMPLETE, data.verify(key1));
            assertNotNull(Signature.find(key2.getName(), data.getSignatures()));
            assertEquals(IntegrityState.COMPLETE, data.verify(key1));
            assertNull(Signature.find(key3.getName(), data.getSignatures()));
            assertEquals(IntegrityState.FAILED_KEY_MISMATCH, data.verify(key3));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
