package com.web3auth.tss_client_android.dkls;

public final class Utilities {

    private static native int jniDklsBatchSize(DKLSError dklsError);

    private static native byte[] jniDklsHashEncode(byte[] msg, DKLSError dklsError);

    private static native byte[] jniDklsLocalSign(byte[] msg, boolean hashOnly, byte[] precomputeBytes, DKLSError dklsError);

    private static native byte[] jniDklsLocalVerify(byte[] msg, boolean hashOnly, byte[] precomputeBytes, long sigFragsPtr, byte[] pkBytes, DKLSError dklsError);

    private static native void jniDklsStringFree(byte[] result);

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
        byte[] messageBytes = message.getBytes();
        byte[] result = jniDklsHashEncode(messageBytes, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDklsStringFree(result);
        return value;
    }

    public static String localSign(String message, boolean hashOnly, Precompute precompute) throws DKLSError {
        byte[] messageBytes = message.getBytes();
        byte[] precomputeStringBytes = precompute.export().getBytes();
        DKLSError dklsError = new DKLSError();
        byte[] result = jniDklsLocalSign(messageBytes, hashOnly, precomputeStringBytes, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDklsStringFree(result);
        return value;
    }

    public static String localVerify(String message, boolean hashOnly, Precompute precompute, SignatureFragments signatureFragments, String pubKey) throws DKLSError {
        byte[] messageBytes = message.getBytes();
        byte[] rBytes = precompute.getR().getBytes();
        byte[] pubKeyBytes = pubKey.getBytes();
        DKLSError dklsError = new DKLSError();
        byte[] result = jniDklsLocalVerify(messageBytes, hashOnly, rBytes, signatureFragments.getPointer(), pubKeyBytes, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        String value = new String(result);
        jniDklsStringFree(result);
        return value;
    }
}

