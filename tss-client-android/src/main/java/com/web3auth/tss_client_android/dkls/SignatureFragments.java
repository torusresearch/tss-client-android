package com.web3auth.tss_client_android.dkls;

public final class SignatureFragments {
    private long pointer;

    public SignatureFragments(String input) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] inputBytes = input.getBytes();
        pointer = jniSignatureFragmentsFromString(inputBytes, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    private native long jniSignatureFragmentsFromString(byte[] input, DKLSError dklsError);

    private native byte[] jniSignatureFragmentsToString(long ptr, DKLSError dklsError);

    private native void jniDklsStringFree(byte[] result);

    private native void jniSignatureFragmentsFree();

    public String export() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] result = jniSignatureFragmentsToString(pointer, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDklsStringFree(result);
        return value;
    }

    public long getPointer() {
        return pointer;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniSignatureFragmentsFree();
    }
}

