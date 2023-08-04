package com.web3auth.tss_client_android.dkls;

public final class Counterparties {
    private long pointer;

    private native long jniCounterparties_From_String(String parties, DKLSError error);

    private native String jniCounterparties_To_String(DKLSError error);

    private native void jniCounterpartiesFree();

    public Counterparties(String parties) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        pointer = jniCounterparties_From_String(parties, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    public String export() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String result = jniCounterparties_To_String(dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        return result;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniCounterpartiesFree();
    }
}
