package com.web3auth.tss_client_android.dkls;

import android.os.Build;

import androidx.annotation.RequiresApi;

import com.web3auth.tss_client_android.client.SECP256K1;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

public final class ChaChaRng {
    private final long pointer;
    @RequiresApi(api = Build.VERSION_CODES.O) // TODO: Compatibility with older versions
    public ChaChaRng() throws DKLSError, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        DKLSError dklsError = new DKLSError();
        SECP256K1.setupBouncyCastle();
        BigInteger privKey = SECP256K1.generatePrivateKey();
        byte[] stateBytes = privKey.toString(16).getBytes(StandardCharsets.UTF_8);
        if (stateBytes == null) {
            throw new DKLSError("Error generating random bytes for generator initialization");
        }
        // convert bytes to base64
        String state = Base64.getEncoder().encodeToString(stateBytes); // This requires Build.VERSION_CODES.O
        long ptr = jniChaChaRng(state, dklsError);
        if (dklsError.code != 5) {
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
