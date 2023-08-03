package com.web3auth.tss_client_android.client;

public class Msg {
    private final String session;
    private final int sender;
    private final int recipient;
    private final String msgType;
    private final String msgData;

    public Msg(String session, int sender, int recipient, String msgType, String msgData) {
        this.session = session;
        this.sender = sender;
        this.recipient = recipient;
        this.msgType = msgType;
        this.msgData = msgData;
    }

    public String getSession() {
        return session;
    }

    public int getSender() {
        return sender;
    }

    public int getRecipient() {
        return recipient;
    }

    public String getMsgType() {
        return msgType;
    }

    public String getMsgData() {
        return msgData;
    }
}
