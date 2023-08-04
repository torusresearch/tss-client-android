package com.web3auth.tss_client_android.dkls;

public final class Precompute {
    private long pointer;

    public Precompute(String precompute) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        pointer = jniPrecomputeFromString(precompute, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }
    private native long jniPrecomputeFromString(String parties, DKLSError error);

    private native String jniPrecomputeToString(DKLSError error);

    private native String jnigetRFromPrecompute(DKLSError error);

    private native void jniPrecomputeFree();

    public String export() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String result = jniPrecomputeToString(dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        return value;
    }

    public String getR() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String result = jnigetRFromPrecompute(dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        return value;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniPrecomputeFree();
    }
}

