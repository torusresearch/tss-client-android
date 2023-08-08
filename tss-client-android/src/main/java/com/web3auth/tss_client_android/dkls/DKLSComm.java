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

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public final class DKLSComm {
    private long pointer;

    @SuppressWarnings("unused") // linter cannot detect that this is called from the JNI
    private String readMsg(String session, int index, int remote, String msgType) throws ExecutionException, InterruptedException {
        if ("ga1_worker_support".equals(msgType)) {
            return "not supported";
        }

        boolean found = false;
        Date now = new Date();
        String result = "";
        while (!found) {
            Message message = MessageQueue.shared().findMessage(session, (int) remote, (int) index, msgType);
            if (message != null) {
                result = message.getMsgData();
                MessageQueue.shared().removeMessage(session, (int) remote, (int) index, msgType);
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
        }
        return result;
    }

    @SuppressWarnings("unused") // linter cannot detect that this is called from the JNI
    private boolean sendMsg(String session, int index, int remote, String  msgType, String msgData) {
        try {
            Pair<TSSEndpoint, TSSSocket> tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, (int) remote);
            TSSSocket tsssocket = tssConnection.second;
            String[] msgTypeParts = msgType.split("~");
            if (msgTypeParts.length >= 2) {
                String tag = msgTypeParts[1];
                System.out.println("dkls: Sending message " + tag + ", sender: " + index + ", receiver: " + remote);
                TssSendMsg msg = new TssSendMsg(session, (int) index, (int) remote, msgType, msgData);
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
                "(Ljava/lang/String;IILjava/lang/String;)Ljava/lang/String;", "sendMsg",
                "(Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;)Z", dklsError);
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

