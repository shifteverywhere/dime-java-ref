//
//  KeyTest.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeUnsupportedProfileException;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class KeyTest {

    @Test
    void getTagTest1() {
        Key key = Key.generateKey(KeyType.IDENTITY);
        assertEquals("KEY", key.getTag());
    }

    @Test
    public void keyTest1() {
        Key key = Key.generateKey(KeyType.IDENTITY);
        assertTrue(key.getProfile() == Profile.UNO);
        assertTrue(key.getKeyType() == KeyType.IDENTITY);
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    public void keyTest2() {
        Key key = Key.generateKey(KeyType.EXCHANGE);
        assertTrue(key.getProfile() == Profile.UNO);
        assertTrue(key.getKeyType() == KeyType.EXCHANGE);
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    public void exportTest1() {
        Key key = Key.generateKey(KeyType.IDENTITY);
        String exported = key.exportItem();
        assertNotNull(exported);
        assertTrue(exported.startsWith(Envelope.HEADER + ":" + Key.TAG));
        assertTrue(exported.split("\\.").length == 2);
    }

    @Test
    public void importTest1() {
        String exported = "Di:KEY.eyJ1aWQiOiIzMTEyNjAxYS0xZWFlLTRkYjgtYTczYi0wNDc0N2EzOGU4N2MiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjM0OjQzLjUxNzIzWiIsImtleSI6IjFoRWl3UjNCcUxZMkV1QVJYZFpVRmFIb2l1aDVSdVg1dlZZNW4xNWVnVTVReFhuU2VYbUFjIiwicHViIjoiMWhQS3luTG1xaWlDa1RHN1JIendtOVFXTXJvaFdFMjV5bTgzQTdZbW9wQ2hIWWF2YUFEemcifQ";
        Key key = (Key)Item.importItem(exported);
        assertEquals(Profile.UNO, key.getProfile());
        assertEquals(KeyType.IDENTITY, key.getKeyType());
        assertEquals(UUID.fromString("3112601a-1eae-4db8-a73b-04747a38e87c"), key.getUniqueId());
        assertEquals(Instant.parse("2021-08-10T06:34:43.51723Z"), key.getIssuedAt()); // TODO: check this
        assertEquals("1hEiwR3BqLY2EuARXdZUFaHoiuh5RuX5vVY5n15egU5QxXnSeXmAc", key.getSecret());
        assertEquals("1hPKynLmqiiCkTG7RHzwm9QWMrohWE25ym83A7YmopChHYavaADzg", key.getPublic());
    }

    @Test
    public void keypairTest3() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY, -1, Profile.UNDEFINED);
        } catch (DimeUnsupportedProfileException e) { return; } // All is well
        assertTrue(false, "This should not happen.");
    }

    @Test
    public void publicOnlyTest1() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY, -1, Profile.UNO);
            assertNotNull(key.getSecret());
            Key pubOnly = key.publicCopy();
            assertNull(pubOnly.getSecret());
            assertEquals(key.getUniqueId(), pubOnly.getUniqueId());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }
/*
    @Test
    public void PublicOnlyTest2() {
        Key key = Key.generateKey(KeyType.IDENTITY, -1, Profile.UNO);
        Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
        message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
        message.Sign(Commons.IssuerKey);
        Key pubOnly = Commons.IssuerKey.PublicCopy();
        message.Verify(pubOnly);
    }
*/
}