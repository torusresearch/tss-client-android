package com.web3auth.tss_client_android.client.TSSmessages;

public class PrecomputeUpdate {
    private final String session;
    private final int party;

    public PrecomputeUpdate(String session, int party) {
        this.session = session;
        this.party = party;
    }

    public String getSession() {
        return session;
    }

    public int getParty() {
        return party;
    }
}

