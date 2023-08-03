package com.web3auth.tss_client_android.dkls;

public final class Precompute {
    private long pointer;

    public Precompute(String precompute) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] precomputeBytes = precompute.getBytes();
        pointer = jniPrecomputeFromString(precomputeBytes, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    private native long jniPrecomputeFromString(byte[] parties, DKLSError error);

    private native byte[] jniPrecomputeToString(long pointer, DKLSError error);

    private native void jniDklsStringFree(byte[] result);

    private native byte[] jnigetR_FromPrecompute(byte[] precomputeBytes, DKLSError error);

    private native void jniPrecomputeFree(long pointer);

    public String export() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] result = jniPrecomputeToString(pointer, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDklsStringFree(result);
        return value;
    }

    public String getR() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String precomputeString = export();
        byte[] precomputeBytes = precomputeString.getBytes();
        byte[] result = jnigetR_FromPrecompute(precomputeBytes, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDklsStringFree(result);
        return value;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniPrecomputeFree(pointer);
    }
}

