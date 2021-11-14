//
//  Message.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.util.Date;
import java.util.UUID;

public class Message extends Item {

    /// PUBLIC ///
    public final static String TAG = "MSG";

    @Override
    public String getTag() {
        return Message.TAG;
    }

    @Override
    public UUID getUniqueId() {
        return null;
    }

    public UUID getAudienceId() {
        return null;
    }

    public UUID getIssuerId() {
        return null;
    }

    public Date getIssuedAt() {
        return null;
    }

    public Date getExpiresAt() {
        return null;
    }

    public UUID getKeyId() {
        return null;
    }

    public String getPublicKye() {
        return null;
    }

    public UUID getLinkedId() {
        return null;
    }

    public Message(UUID issuerId, double validFor) {

    }

    public Message(UUID audienceId, UUID issuerId, double validFor) {

    }

    @Override
    public void sign(Key key) {

    }

    @Override
    public String toEncoded() {
        return super.toEncoded();
    }

    /*    protected static Key fromEncoded(String encoded) {
        return null;
    }*/

    @Override
    public void verify(Key key) {
        super.verify(key);
    }

    public void verify(String publicKey, Item linkedItem) {
        verify(new Key(publicKey), linkedItem);
    }

    public void verify(Key key, Item linkedItem) {

    }

    public void setPayload(byte[] payload) {

    }

    public void setPayload(byte[] payload, Key localKey, Key remoteKey, byte[] salt) {

    }

    public byte[] getPayload() {
        return null;
    }

    public byte[] getPayload(Key localKey, Key remoteKey, byte[] salt) {
        return null;
    }

    public void LinkItem(Item item) {

    }

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) {

    }

    @Override
    protected String encode() {
        return null;
    }

    /// PRIVATE ///

    private String _payload;
}
