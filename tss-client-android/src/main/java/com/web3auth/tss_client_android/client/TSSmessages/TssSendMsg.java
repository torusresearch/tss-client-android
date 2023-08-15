package com.web3auth.tss_client_android.client.TSSmessages;

import org.json.JSONException;
import org.json.JSONObject;

public class TssSendMsg {

    private final String session;
    private final int index;
    private final int recipient;
    private final String msg_type;
    private final String msg_data;

    public TssSendMsg(String session, int index, int recipient, String msg_type, String msg_data) {
        this.session = session;
        this.index = index;
        this.recipient = recipient;
        this.msg_type = msg_type;
        this.msg_data = msg_data;
    }

    public String getSession() {
        return session;
    }

    public int getIndex() {
        return index;
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

    public JSONObject toJsonObject() throws JSONException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("session", session);
        jsonObject.put("sender", index);
        jsonObject.put("recipient", recipient);
        jsonObject.put("msg_type", msg_type);
        jsonObject.put("msg_data", msg_data);
        return jsonObject;
    }
}

