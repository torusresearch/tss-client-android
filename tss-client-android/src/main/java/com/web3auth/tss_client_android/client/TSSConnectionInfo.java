package com.web3auth.tss_client_android.client;

import androidx.core.util.Pair;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public final class TSSConnectionInfo {

    private static final TSSConnectionInfo instance = new TSSConnectionInfo();
    private final List<TSSEndpoint> endpoints = new ArrayList<>();
    private final List<TSSSocket> socketManagers = new ArrayList<>();

    private TSSConnectionInfo() {
    }

    public static TSSConnectionInfo getShared() {
        return instance;
    }

    public void addInfo(String session, int party, URL endpoint, URL socketUrl) {
        synchronized (TSSConnectionInfo.class) {
            endpoints.add(new TSSEndpoint(session, party, endpoint));
            socketManagers.add(new TSSSocket(session, party, socketUrl));
        }
    }

    public Pair<TSSEndpoint, TSSSocket> lookupEndpoint(String session, int party) {
        synchronized (TSSConnectionInfo.class) {
            TSSEndpoint endpoint = null;
            TSSSocket mgr = null;
            for (TSSEndpoint ep : endpoints) {
                if (ep.getSession().equals(session) && ep.getParty() == party) {
                    endpoint = ep;
                    break;
                }
            }
            for (TSSSocket socket : socketManagers) {
                if (socket.getSession().equals(session) && socket.getParty() == party) {
                    mgr = socket;
                    break;
                }
            }
            return new Pair<>(endpoint, mgr);
        }
    }

    public List<TSSEndpoint> allEndpoints(String session) {
        synchronized (TSSConnectionInfo.class) {
            List<TSSEndpoint> sessionEndpoints = new ArrayList<>();
            for (TSSEndpoint endpoint : endpoints) {
                if (endpoint.getSession().equals(session)) {
                    sessionEndpoints.add(endpoint);
                }
            }
            return sessionEndpoints;
        }
    }

    public void removeInfo(String session, int party) {
        synchronized (TSSConnectionInfo.class) {
            endpoints.removeIf(ep -> ep.getSession().equals(session) && ep.getParty() == party);
            socketManagers.removeIf(socket -> socket.getSession().equals(session) && socket.getParty() == party);
        }
    }

    public void removeAll(String session) {
        synchronized (TSSConnectionInfo.class) {
            endpoints.removeIf(endpoint -> endpoint.getSession().equals(session));
            socketManagers.removeIf(socket -> socket.getSession().equals(session));
        }
    }
}

