/*
package com.web3auth.tss_client_android;

import com.google.gson.Gson;
import com.web3auth.tss_client_android.client.SECP256K1;
import com.web3auth.tss_client_android.client.TSSHelpers;

import org.web3j.crypto.ECDSASignature;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TssClientTests {

    static class Delimiters {
        static final char Delimiter1 = '\u001c';
        static final char Delimiter2 = '\u0015';
        static final char Delimiter3 = '\u0016';
        static final char Delimiter4 = '\u0017';
    }

    private final List<String> privateKeys = new ArrayList<>();

    private String session = "";
    private BigInteger share = new BigInteger("0");
    private Gson gson = new Gson();

    private List<String> getPrivateKeys() {
        privateKeys.add("da4841d60f47652584aea0ab578660b353dbcd6907940ed0a295c9d95aabadd0");
        privateKeys.add("e7ef4a9dcc9c0305ec9e56c79128f5c12413b976309368c35c11f3297459994b");
        privateKeys.add("31534072a75a1d8b7f07c1f29930533ae44166f44ce08a4a23126b6dcb8b6efe");
        privateKeys.add("f2588097a5df3911e4826e13dce2b6f4afb798bb8756675b17d4195db900af20");
        privateKeys.add("5513438cd00c901ff362e25ae08aa723495bea89ab5a53ce165730bc1d9a0280");
        return privateKeys;
    }

    private List<String> getSignatures() {
        Map<String, Object> tokenData = new HashMap<>();
        tokenData.put("exp", new Date().getTime() + 3000 * 60);
        tokenData.put("temp_key_x", "test_key_x");
        tokenData.put("temp_key_y", "test_key_y");
        tokenData.put("verifier_name", "test_verifier_name");
        tokenData.put("verifier_id", "test_verifier_id");

        String token = Base64.getEncoder().encodeToString(gson.toJson(tokenData).getBytes());

        List<String> sigs = new ArrayList<>();
        for (String item : privateKeys) {
            byte[] hash = TSSHelpers.hashMessage(token);
            ECDSASignature signature = SECP256K1.signForRecovery(hash, Utils.hexStringToByteArray(item));
            String sig = signature.getR().toString(16) + signature.getS().toString(16)
                    + String.format("%02X", signature.getV());
            Map<String, Object> msg = new HashMap<>();
            msg.put("data", token);
            msg.put("sig", sig);
            String jsonData = gson.toJson(msg);
            sigs.add(jsonData);
        }

        return sigs;
    }

    private static List<Object> setupMockShares(List<String> endpoints, List<Integer> parties, int localClientIndex, String session) {
        byte[] privKey = SECP256K1.generatePrivateKey();
        BigInteger publicKey = SECP256K1.privateToPublic(privKey);

        distributeShares(privKey, parties, endpoints, localClientIndex, session);
        List<Object> result = new ArrayList<>();
        result.add(privKey);
        result.add(publicKey);
        return result;
    }

    private static List<Object> generateEndpoints(int parties, int clientIndex) {
        List<String> endPoints = new ArrayList<>();
        List<String> tssWSEndpoints = new ArrayList<>();
        List<Integer> partyIndexes = new ArrayList<>();
        int serverPortOffset = 0;
        int basePort = 8000;
        for (int i = 0; i < parties; i++) {
            partyIndexes.add(i);
            if (i == clientIndex) {
                endPoints.add(null);
                tssWSEndpoints.add(null);
            } else {
                endPoints.add("http://localhost:" + (basePort + serverPortOffset));
                tssWSEndpoints.add("http://localhost:" + (basePort + serverPortOffset));
                serverPortOffset++;
            }
        }
        List<Object> result = new ArrayList<>();
        result.add(endPoints);
        result.add(tssWSEndpoints);
        result.add(partyIndexes);
        return result;
    }


}
*/
