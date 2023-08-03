package com.web3auth.tss_client_android.dkls;

import java.nio.charset.StandardCharsets;

public final class DKLSComm {
    private long pointer;

    public DKLSComm(String session, int index, int parties, ReadMsgCallback readMsgCallback, SendMsgCallback sendMsgCallback) throws DKLSError {
        DKLSError dklsError = new DKLSError();

        byte[] sessionBytes = session.getBytes(StandardCharsets.UTF_8);
        long result = jniDklsComm(index, parties, sessionBytes, readMsgCallback, sendMsgCallback, dklsError);

        if (dklsError.code != 0) {
            throw dklsError;
        }

        pointer = result;
    }

    private native long jniDklsComm(int index, int parties, byte[] sessionBytes, ReadMsgCallback readMsgCallback, SendMsgCallback sendMsgCallback,
                                    DKLSError dklsError);

    private native void jniDklsCommFree();

    public long getPointer() {
        return pointer;
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

