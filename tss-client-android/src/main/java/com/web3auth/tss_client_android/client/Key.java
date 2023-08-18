package com.web3auth.tss_client_android.client;

public class Key {
    private final String x;
    private final String y;

    public Key(String x, String y) {
        this.x = x;
        this.y = y;
    }

    public String getX() {
        return x;
    }

    public String getY() {
        return y;
    }
}
