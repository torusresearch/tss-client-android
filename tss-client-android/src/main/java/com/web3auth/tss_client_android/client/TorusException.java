package com.web3auth.tss_client_android.client;

public class TorusException extends Exception {
    public TorusException(String msg) {
        super(msg);
    }

    public TorusException(String msg, Throwable err) {
        super(msg, err);
    }
}