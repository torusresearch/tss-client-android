package com.web3auth.tss_client_android.TSSmessages;

public class RecvMsg {
    private String session;
    private int sender;
    private int recipient;
    private String msg_type;
    private String msg_data;

    public RecvMsg() {
    }

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

    public void setSession(String session) {
        this.session = session;
    }

    public int getSender() {
        return sender;
    }

    public void setSender(int sender) {
        this.sender = sender;
    }

    public int getRecipient() {
        return recipient;
    }

    public void setRecipient(int recipient) {
        this.recipient = recipient;
    }

    public String getMsg_type() {
        return msg_type;
    }

    public void setMsg_type(String msg_type) {
        this.msg_type = msg_type;
    }

    public String getMsg_data() {
        return msg_data;
    }

    public void setMsg_data(String msg_data) {
        this.msg_data = msg_data;
    }
}

