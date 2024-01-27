//
//  ItemTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.keyring.IntegrityState;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class ItemTest {

    @Test
    void verifyTest1() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), Dime.VALID_FOR_1_MINUTE, null, null);
            key.addItemLink(Commons.getIssuerIdentity());
            key.addItemLink(Commons.getAudienceIdentity());
            key.sign(key);
            assertEquals(IntegrityState.PARTIALLY_COMPLETE, key.verify(key));
            assertEquals(IntegrityState.INTACT, key.verify(key, List.of(Commons.getIssuerIdentity())));
            assertEquals(IntegrityState.COMPLETE, key.verify(key, List.of(Commons.getIssuerIdentity(), Commons.getAudienceIdentity())));
            assertEquals(IntegrityState.INTACT, key.verify(key, List.of(Commons.getIssuerIdentity(), Commons.getAudienceIdentity(), Commons.getIssuerIdentity())));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest2() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            key.addItemLink(Commons.getIssuerIdentity());
            key.addItemLink(Commons.getAudienceIdentity());
            key.sign(key);
            assertEquals(IntegrityState.COMPLETE, key.verify(key, List.of(Commons.getIssuerIdentity(), Commons.getAudienceIdentity())));
            assertEquals(IntegrityState.FAILED_LINKED_ITEM_MISMATCH, key.verify(key, List.of(Commons.getTrustedIdentity(), Commons.getIntermediateIdentity())));
            assertEquals(IntegrityState.FAILED_LINKED_ITEM_MISMATCH, key.verify(key, List.of(Commons.getTrustedIdentity(), Commons.getIssuerIdentity())));
            assertEquals(IntegrityState.INTACT, key.verify(key, List.of(Commons.getIssuerIdentity())));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest3() {
        try {
            Dime.setOverrideTime(null);
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), Dime.VALID_FOR_1_MINUTE, null, null);
            key.sign(key);
            Dime.setOverrideTime(Instant.now().plusSeconds(Dime.VALID_FOR_1_MINUTE * 2));
            assertEquals(IntegrityState.FAILED_USED_AFTER_EXPIRED, key.verify(key));
            Dime.setOverrideTime(Instant.now().minusSeconds(Dime.VALID_FOR_1_MINUTE));
            assertEquals(IntegrityState.FAILED_USED_BEFORE_ISSUED, key.verify(key));
            Dime.setOverrideTime(null);
            assertEquals(IntegrityState.COMPLETE, key.verify(key));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest4() {
        try {
            Key key = Key.generateKey(KeyCapability.ENCRYPT);
            key.putClaim(Claim.ISS, Commons.getIssuerIdentity().getClaim(Claim.SUB));
            key.sign(Commons.getIssuerKey());
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getIssuerIdentity()));
            assertEquals(IntegrityState.FAILED_ISSUER_MISMATCH, key.verify(Commons.getAudienceIdentity()));
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getIssuerIdentity().getPublicKey()));
            assertEquals(IntegrityState.FAILED_KEY_MISMATCH, key.verify(Commons.getAudienceIdentity().getPublicKey()));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
