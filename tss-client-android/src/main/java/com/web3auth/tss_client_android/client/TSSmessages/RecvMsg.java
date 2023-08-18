package com.web3auth.tss_client_android.client.TSSmessages;

public class RecvMsg {
    public final String session;
    public final int sender;
    public final int recipient;
    public final String msg_type;
    public final String msg_data;

    public RecvMsg(String session, int sender, int recipient, String msg_type, String msg_data) {
        this.session = session;
        this.sender = sender;
        this.recipient = recipient;
        this.msg_type = msg_type;
        this.msg_data = msg_data;
    }
}

