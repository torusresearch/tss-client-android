package com.web3auth.tss_client_android.TSSmessages;

public class PrecomputeUpdate {
    private String session;
    private int party;

    public PrecomputeUpdate() {
    }

    public PrecomputeUpdate(String session, int party) {
        this.session = session;
        this.party = party;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public int getParty() {
        return party;
    }

    public void setParty(int party) {
        this.party = party;
    }
}

