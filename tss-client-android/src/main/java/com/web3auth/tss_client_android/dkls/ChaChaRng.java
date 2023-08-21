package com.web3auth.tss_client_android.dkls;

import com.web3auth.tss_client_android.client.util.Secp256k1;

import org.bouncycastle.util.Arrays;

public final class ChaChaRng {
    //Note: Linter cannot detect jni usage of this variable, hence the need to supress warnings
    @SuppressWarnings("all")
    private final long pointer;

    public ChaChaRng() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] privateKeyBytes = Secp256k1.GenerateECKey();
        byte[] stateBytes = (privateKeyBytes.length > 32) ? Arrays.copyOfRange(privateKeyBytes, privateKeyBytes.length - 32, privateKeyBytes.length) :
                privateKeyBytes;
        // convert bytes to base64
        String state = java.util.Base64.getEncoder().encodeToString(stateBytes);
        long ptr = jniChaChaRng(state, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        pointer = ptr;
    }

    private native long jniChaChaRng(String state, DKLSError error);

    private native void jniChaChaRngFree();

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniChaChaRngFree();
    }
}
