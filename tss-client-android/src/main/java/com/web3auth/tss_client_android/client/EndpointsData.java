package com.web3auth.tss_client_android.client;

import java.util.List;

public class EndpointsData {
    private final List<String> endpoints;
    private final List<String> tssWSEndpoints;
    private final List<Integer> partyIndexes;

    public EndpointsData(List<String> endpoints, List<String> tssWSEndpoints, List<Integer> partyIndexes) {
        this.endpoints = endpoints;
        this.tssWSEndpoints = tssWSEndpoints;
        this.partyIndexes = partyIndexes;
    }

    public List<String> getEndpoints() {
        return endpoints;
    }

    public List<String> getTssWSEndpoints() {
        return tssWSEndpoints;
    }

    public List<Integer> getPartyIndexes() {
        return partyIndexes;
    }
}

