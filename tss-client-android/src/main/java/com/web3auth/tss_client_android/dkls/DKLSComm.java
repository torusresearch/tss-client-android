package com.web3auth.tss_client_android.dkls;

import java.nio.charset.StandardCharsets;

public final class DKLSComm {
    private long pointer;

    private native long jniDklsComm(int index, int parties, String session, ReadMsgCallback readMsgCallback, SendMsgCallback sendMsgCallback,
                                    DKLSError dklsError);

    private native void jniDklsCommFree();

    public DKLSComm(String session, int index, int parties, ReadMsgCallback readMsgCallback, SendMsgCallback sendMsgCallback) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        long result = jniDklsComm(index, parties, session, readMsgCallback, sendMsgCallback, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        pointer = result;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniDklsCommFree();
    }

    public interface ReadMsgCallback {
        String readMsg(String session, long index, long remote, String msgType);
    }

    public interface SendMsgCallback {
        boolean sendMsg(String session, long index, long recipient, String msgType, String msgData);
    }
}

