package com.web3auth.tss_client_android.dkls;

public final class ChaChaRng {
    private final long pointer;

    public ChaChaRng() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        // generate Private key
        // convert bytes to base64
        long ptr = jniChaChaRng("", dklsError);
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

    public long getPointer() {
        return pointer;
    }
}
