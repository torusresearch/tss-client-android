package com.web3auth.tss_client_android.client;

import java.net.URL;

public final class TSSEndpoint {
    private final String session;
    private final int party;
    private final URL url;

    public TSSEndpoint(String session, int party, URL url) {
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

    public URL getUrl() {
        return url;
    }
}

