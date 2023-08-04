package com.web3auth.tss_client_android.dkls;

public final class ThresholdSigner {
    private long pointer;

    public ThresholdSigner(String session, int playerIndex, int parties, int threshold, String share, String publicKey) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        pointer = jniThresholdSigner(session, playerIndex, parties, threshold, share, publicKey, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    private native long jniThresholdSigner(String session, int playerIndex, int parties, int threshold, String share, String pk, DKLSError dklsError);

    private native boolean jniThresholdSignerSetup(ChaChaRng chacha, DKLSComm dklsComm, DKLSError dklsError);

    private native String jniThresholdSignerPrecompute(Counterparties counterParties, ChaChaRng chacha, DKLSComm dklsComm, DKLSError dklsError);

    private native void jniThresholdSignerFree();

    public boolean setup(ChaChaRng rng, DKLSComm comm) {
        boolean result = jniThresholdSignerSetup(rng, comm, new DKLSError());
        return result;
    }

    public Precompute precompute(Counterparties parties, ChaChaRng rng, DKLSComm comm) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String result = jniThresholdSignerPrecompute(parties, rng, comm, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        return new Precompute(result);
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniThresholdSignerFree();
    }
}

