package com.web3auth.tss_client_android.TSSmessages;

import org.json.JSONException;
import org.json.JSONObject;

public class TssSendMsg {

    private String session;
    private int index;
    private int recipient;
    private String msg_type;
    private String msg_data;

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

    public void setSession(String session) {
        this.session = session;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
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

