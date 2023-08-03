package com.web3auth.tss_client_android.dkls;

import androidx.annotation.NonNull;

public class DKLSError extends Throwable {
    public int code = -1;

    @NonNull
    @Override
    public String toString() {
        return "RuntimeError{" +
                "code=" + code +
                '}';
    }
}
