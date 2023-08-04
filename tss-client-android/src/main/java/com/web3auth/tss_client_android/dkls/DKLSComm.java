package com.web3auth.tss_client_android.dkls;

public final class DKLSComm {
    private long pointer;

    @SuppressWarnings("unused") // linter cannot detect that this is called from the JNI
    private String readMsg(String session, int index, int remote, String  msgType) {
        //Todo: Implementation
        return "";
    }

    @SuppressWarnings("unused") // linter cannot detect that this is called from the JNI
    private Boolean SendMsg(String session, int index, int remote, String  msgType, String msgData) {
        //Todo: Implementation
        return false;
    }

    private native long jniDklsComm(int index, int parties, String session, String readMsgCallback, String readMsgCallbackSig, String sendMsgCallback, String sendMessageCallbackSig,
                                    DKLSError dklsError);

    private native void jniDklsCommFree();

    public DKLSComm(String session, int index, int parties) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        long result = jniDklsComm(index, parties, session,
                "readMsg",
                "(Ljava/lang/String;IILjava/lang/String;)Ljava/lang/String;", "sendMsg",
                "(Ljava/lang/String;IILjava/lang/String;)Ljava/lang/String;)Z", dklsError);
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
}

