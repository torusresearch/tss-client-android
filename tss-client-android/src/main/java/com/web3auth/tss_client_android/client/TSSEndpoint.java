package com.web3auth.tss_client_android.client;

public final class TSSEndpoint {
    private final String session;
    private final int party;
    private final String url;

    public TSSEndpoint(String session, int party, String url) {
        this.session = session;
        this.party = party;
        this.url = url;
    }

    public String getSession() {
        return session;
    }

    public int getParty() {
        return party;
    }

    public String getUrl() {
        return url;
    }
}

