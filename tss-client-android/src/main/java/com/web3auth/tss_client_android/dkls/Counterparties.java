package com.web3auth.tss_client_android.dkls;

public final class Counterparties {
    private long pointer;

    public Counterparties(String parties) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] partiesBytes = parties.getBytes();
        pointer = jniCounterparties_From_String(String.valueOf(partiesBytes), dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    private native long jniCounterparties_From_String(String parties, DKLSError error);

    private native byte[] jniCounterparties_To_String(long pointer, DKLSError error);

    private native void jniDkls_string_free(byte[] result);

    private native void jniCounterpartiesFree(long pointer);

    public String export() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] result = jniCounterparties_To_String(pointer, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDkls_string_free(result);
        return value;
    }

    public long getPointer() {
        return pointer;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniCounterpartiesFree(pointer);
    }
}
