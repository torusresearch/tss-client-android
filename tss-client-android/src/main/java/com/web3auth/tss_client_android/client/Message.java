package com.web3auth.tss_client_android.client;

public class Message {
    private final String session;
    private final long sender;
    private final long recipient;
    private final String msgType;
    private final String msgData;

    public Message(String session, long sender, long recipient, String msgType, String msgData) {
        this.session = session;
        this.sender = sender;
        this.recipient = recipient;
        this.msgType = msgType;
        this.msgData = msgData;
    }

    public String getSession() {
        return session;
    }

    public long getSender() {
        return sender;
    }

    public long getRecipient() {
        return recipient;
    }

    public String getMsgType() {
        return msgType;
    }

    public String getMsgData() {
        return msgData;
    }
}

