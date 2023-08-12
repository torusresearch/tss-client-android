package com.web3auth.tss_client_android.dkls;

public final class SignatureFragments {
    private final long pointer;

    private native long jniSignatureFragmentsFromString(String input, DKLSError dklsError);

    private native String jniSignatureFragmentsToString( DKLSError dklsError);

    private native void jniSignatureFragmentsFree();

    public SignatureFragments(String input) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        pointer = jniSignatureFragmentsFromString(input, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
    }

    public String export() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String result = jniSignatureFragmentsToString(dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        return result;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniSignatureFragmentsFree();
    }
}

