package com.web3auth.tss_client_android.dkls;

public final class Utilities {

    public static native int jniDklsBatchSize(DKLSError dklsError);

    private static native String jniDklsHashEncode(String msg, DKLSError dklsError);

    private static native String jniDklsLocalSign(String msg, boolean hashOnly, String precompute, DKLSError dklsError);

    private static native String jniDklsLocalVerify(String msg, boolean hashOnly, String r, SignatureFragments sigFrags, String pk, DKLSError dklsError);

    public static int batchSize() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        int result = jniDklsBatchSize(dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        return result;
    }

    public static String hashEncode(String message) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String result = jniDklsHashEncode(message, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        return result;
    }

    public static String localSign(String message, boolean hashOnly, Precompute precompute) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String input = precompute.export();
        String result = jniDklsLocalSign(message, hashOnly, input, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        return result;
    }

    public static String localVerify(String message, boolean hashOnly, Precompute precompute, SignatureFragments signatureFragments, String pubKey) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        String r = precompute.getR();
        String result = jniDklsLocalVerify(message, hashOnly, r, signatureFragments, pubKey, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        return result;
    }
}

