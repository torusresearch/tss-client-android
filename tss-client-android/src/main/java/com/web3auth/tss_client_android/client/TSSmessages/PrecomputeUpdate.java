package com.web3auth.tss_client_android.client.TSSmessages;

public class PrecomputeUpdate {
    public final String session;
    public final int party;

    public PrecomputeUpdate(String session, int party) {
        this.session = session;
        this.party = party;
    }
}

