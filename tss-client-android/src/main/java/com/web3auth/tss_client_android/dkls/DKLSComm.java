package com.web3auth.tss_client_android.dkls;

import androidx.core.util.Pair;

import com.web3auth.tss_client_android.TSSmessages.TssSendMsg;
import com.web3auth.tss_client_android.client.EventQueue;
import com.web3auth.tss_client_android.client.EventType;
import com.web3auth.tss_client_android.client.Message;
import com.web3auth.tss_client_android.client.MessageQueue;
import com.web3auth.tss_client_android.client.TSSConnectionInfo;
import com.web3auth.tss_client_android.client.TSSEndpoint;
import com.web3auth.tss_client_android.client.TSSSocket;

import java.math.BigInteger;
import java.util.Date;
import java.util.Map;

public final class DKLSComm {
    private final long pointer;

    @SuppressWarnings("unused") // linter cannot detect that this is called from the JNI
    private String readMsg(String session, byte[] index_bytes, byte[] remote_bytes, String msgType) {
        if ("ga1_worker_support".equals(msgType)) {
            return "not supported";
        }

        BigInteger index = new BigInteger(1, index_bytes);
        BigInteger remote = new BigInteger(1, remote_bytes);

        boolean found = false;
        Date now = new Date();
        String result = "";
        while (!found) {
            try {
                Message message = MessageQueue.shared().findMessage(session, remote.intValue(), index.intValue(), msgType);
                if (message != null) {
                    result = message.getMsgData();
                    MessageQueue.shared().removeMessage(session, remote.intValue(), index.intValue(), msgType);
                    found = true;
                }
                if (new Date().getTime() > now.getTime() + 5000 && !found) { // 5 second wait max
                    System.out.println("Failed to receive message in reasonable time");
                    break;
                } else {
                    Map<EventType, Integer> counts = EventQueue.shared().countEvents(session);
                    if (counts.get(EventType.PRECOMPUTE_ERROR) != null && counts.get(EventType.PRECOMPUTE_ERROR) > 0) {
                        break;
                    }
                }
            } catch(Exception _e) {
                // no-op, result goes back empty
            }
        }
        return result;
    }

    @SuppressWarnings("unused") // linter cannot detect that this is called from the JNI
    private boolean sendMsg(String session, byte[] index_bytes, byte[] remote_bytes, String  msgType, String msgData) {
        try {
            BigInteger index = new BigInteger(1, index_bytes);
            BigInteger remote = new BigInteger(1, remote_bytes);

            Pair<TSSEndpoint, TSSSocket> tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, remote.intValue());
            TSSSocket tsssocket = tssConnection.second;
            String[] msgTypeParts = msgType.split("~");
            if (msgTypeParts.length >= 2) {
                String tag = msgTypeParts[1];
                System.out.println("dkls: Sending message " + tag + ", sender: " + index + ", receiver: " + remote);
                TssSendMsg msg = new TssSendMsg(session, index.intValue(), remote.intValue(), msgType, msgData);
                if (tsssocket != null && tsssocket.getSocket() != null) {
                    System.out.println("socket send websocket: " + tsssocket.getSocket().id() + ": " + index + "->" + remote + ", " + msgType);
                    tsssocket.getSocket().emit("send_msg", msg);
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private native long jniDklsComm(int index, int parties, String session, String readMsgCallback, String readMsgCallbackSig, String sendMsgCallback, String sendMessageCallbackSig,
                                    DKLSError dklsError);

    private native void jniDklsCommFree();

    public DKLSComm(String session, int index, int parties) throws DKLSError {
        DKLSError dklsError = new DKLSError();
        long result = jniDklsComm(index, parties, session,
                "readMsg",
                "(Ljava/lang/String;[B[BLjava/lang/String;)Ljava/lang/String;", "sendMsg",
                "(Ljava/lang/String;[B[BLjava/lang/String;Ljava/lang/String;)Z", dklsError);
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

