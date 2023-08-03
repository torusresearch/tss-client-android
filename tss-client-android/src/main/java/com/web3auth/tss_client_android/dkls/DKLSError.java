package com.web3auth.tss_client_android.dkls;

public class DKLSError extends Throwable {
    public int code = -1;
    private String message;

    public DKLSError() {

    }

    public DKLSError(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "RuntimeError{" +
                "code=" + code +
                '}';
    }
}
