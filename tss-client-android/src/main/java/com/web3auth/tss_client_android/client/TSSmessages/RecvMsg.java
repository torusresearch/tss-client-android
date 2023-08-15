package com.web3auth.tss_client_android.client.TSSmessages;

public class RecvMsg {
    private final String session;
    private final int sender;
    private final int recipient;
    private final String msg_type;
    private final String msg_data;

    public RecvMsg(String session, int sender, int recipient, String msg_type, String msg_data) {
        this.session = session;
        this.sender = sender;
        this.recipient = recipient;
        this.msg_type = msg_type;
        this.msg_data = msg_data;
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
        return msg_type;
    }

    public String getMsgData() {
        return msg_data;
    }
}

