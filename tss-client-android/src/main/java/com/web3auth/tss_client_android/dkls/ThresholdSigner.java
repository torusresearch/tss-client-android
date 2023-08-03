package com.web3auth.tss_client_android.dkls;

public final class ThresholdSigner {
    private long pointer;

    public ThresholdSigner(String session, int playerIndex, int parties, int threshold, String share, String publicKey) throws DKLSError {
        byte[] sessionBytes = session.getBytes();
        byte[] shareBytes = share.getBytes();
        byte[] pkBytes = publicKey.getBytes();
        DKLSError dklsError = new DKLSError();
        pointer = jniThreaholdSigner(sessionBytes, playerIndex, parties, threshold, shareBytes, pkBytes, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    private native long jniThreaholdSigner(byte[] sessionBytes, int playerIndex, int parties, int threshold, byte[] shareBytes, byte[] pkBytes, DKLSError dklsError);

    private native boolean jniThresholdSignerSetup(long ptr, long chachaPtr, long dklsCommPtr, DKLSError dklsError);

    private native byte[] jniThresholdSignerPrecompute(long counterPartiesPtr, long ptr, long chachaPtr, long dklsCommPtr, DKLSError dklsError);

    private native void jniDkls_string_free(byte[] result);

    private native void jniThresholdSignerFree();

    public boolean setup(ChaChaRng rng, DKLSComm comm) {
        boolean result = jniThresholdSignerSetup(pointer, rng.getPointer(), comm.getPointer(), new DKLSError());
        return result;
    }

    public Precompute precompute(Counterparties parties, ChaChaRng rng, DKLSComm comm) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] result = jniThresholdSignerPrecompute(parties.getPointer(), pointer, rng.getPointer(), comm.getPointer(), dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDkls_string_free(result);
        return new Precompute(value);
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniThresholdSignerFree();
    }
}

