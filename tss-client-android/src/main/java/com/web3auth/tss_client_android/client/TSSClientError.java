package com.web3auth.tss_client_android.client;

public class TSSClientError extends Exception {
    private final String message;

    public TSSClientError(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}

