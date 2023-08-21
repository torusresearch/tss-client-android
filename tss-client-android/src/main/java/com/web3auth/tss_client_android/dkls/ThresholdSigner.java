package com.web3auth.tss_client_android.dkls;

public final class ThresholdSigner {
    //Note: Linter cannot detect jni usage of this variable, hence the need to supress warnings
    @SuppressWarnings("all")
    private final long pointer;

    public ThresholdSigner(String session, int playerIndex, int parties, int threshold, String share, String publicKey) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        pointer = jniThresholdSigner(session, playerIndex, parties, threshold, share, publicKey, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    private native long jniThresholdSigner(String session, int playerIndex, int parties, int threshold, String share, String pk, DKLSError dklsError);

    private native boolean jniThresholdSignerSetup(ChaChaRng chacha, DKLSComm dklsComm);

    private native String jniThresholdSignerPrecompute(Counterparties counterParties, ChaChaRng chacha, DKLSComm dklsComm, DKLSError dklsError);

    private native void jniThresholdSignerFree();

    public boolean setup(ChaChaRng rng, DKLSComm comm) {
        return jniThresholdSignerSetup(rng, comm);
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

