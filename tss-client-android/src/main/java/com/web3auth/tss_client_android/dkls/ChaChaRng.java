package com.web3auth.tss_client_android.dkls;
import com.web3auth.tss_client_android.client.SECP256K1;
import org.bouncycastle.util.Arrays;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public final class ChaChaRng {
    //Note: Linter cannot detect jni usage of this variable, hence the need to supress warnings
    @SuppressWarnings("all")
    private final long pointer;

    public ChaChaRng() throws DKLSError, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        DKLSError dklsError = new DKLSError();
        BigInteger privKey = SECP256K1.generatePrivateKey();
        byte[] privateKeyBytes = privKey.toByteArray();
        byte[] stateBytes = (privateKeyBytes.length > 32) ? Arrays.copyOfRange(privateKeyBytes, privKey.toByteArray().length - 32, privKey.toByteArray().length) :
            privateKeyBytes;
        // convert bytes to base64
        String state = android.util.Base64.encodeToString(stateBytes, android.util.Base64.DEFAULT);
        long ptr = jniChaChaRng(state, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        pointer = ptr;
    }

    private native long jniChaChaRng(String state, DKLSError error);

    private native void jniChaChaRngFree();

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniChaChaRngFree();
    }
}
