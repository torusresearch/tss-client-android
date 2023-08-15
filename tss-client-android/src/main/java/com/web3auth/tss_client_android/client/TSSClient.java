package com.web3auth.tss_client_android.client;

import static com.web3auth.tss_client_android.client.AES256CBC.bytesToHex;

import androidx.core.util.Pair;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.web3auth.tss_client_android.dkls.ChaChaRng;
import com.web3auth.tss_client_android.dkls.Counterparties;
import com.web3auth.tss_client_android.dkls.DKLSComm;
import com.web3auth.tss_client_android.dkls.DKLSError;
import com.web3auth.tss_client_android.dkls.Precompute;
import com.web3auth.tss_client_android.dkls.SignatureFragments;
import com.web3auth.tss_client_android.dkls.ThresholdSigner;
import com.web3auth.tss_client_android.dkls.Utilities;

import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import kotlin.Triple;

public class TSSClient {

    private static final String CURVE_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    public static final BigInteger modulusValueUnsigned = new BigInteger(CURVE_N, 16);
    public static final BigInteger modulusValueSigned = new BigInteger(CURVE_N, 16);

    private final String session;
    private final int parties;
    private final ThresholdSigner signer;
    private final DKLSComm comm;
    private final ChaChaRng rng;
    private final long index;
    private final boolean ready = false;
    private final String pubKey;
    private boolean consumed = false;
    private final boolean _sLessThanHalf = true;

    public TSSClient(String session, long index, int[] parties, String[] endpoints,
                     String[] tssSocketEndpoints, String share, String pubKey) throws TSSClientError, DKLSError, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, ExecutionException, InterruptedException {
        if (parties.length != tssSocketEndpoints.length) {
            throw new TSSClientError("Parties and socket length must be equal");
        }

        if (parties.length != endpoints.length) {
            throw new TSSClientError("Parties and endpoint length must be equal");
        }

        this.index = index;
        this.session = session;
        this.parties = parties.length;
        this.pubKey = pubKey;

        for (int i = 0; i < endpoints.length; i++) {
            if (i != this.index) {
                TSSConnectionInfo.getShared().addInfo(session, i, endpoints[i], tssSocketEndpoints[i]);
            }
        }

        comm = new DKLSComm(session, (int) this.index, parties.length);

        rng = new ChaChaRng();

        signer = new ThresholdSigner(session, (int) this.index, parties.length, parties.length, share, pubKey);
    }

    public static String sid(String session) {
        String[] sessionParts = session.split(String.valueOf(Delimiters.Delimiter4));
        if (sessionParts.length >= 2) {
            return sessionParts[1];
        } else {
            throw new RuntimeException("Invalid session format");
        }
    }

    private boolean setup() {
        return signer.setup(rng, comm);
    }

    public Precompute precompute(Map<String, String> serverCoeffs, List<String> signatures) throws TSSClientError, DKLSError {
        boolean local_servers = System.getProperty("LOCAL_SERVERS") != null;
        EventQueue.shared().updateFocus(new Date());
        for (int i = 0; i < parties; i++) {
            if (i != index) {
                try {
                    TSSSocket tssSocket = TSSConnectionInfo.getShared().lookupEndpoint(session, i).second;
                    if (tssSocket.getSocket() == null && tssSocket.getSocket().id() == null) {
                        throw new TSSClientError("socket not connected yet, party: " + i + ", session: " + session);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        for (int i = 0; i < parties; i++) {
            long party = i;
            if (party != index) {
                try {
                    Pair<TSSEndpoint, TSSSocket> tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, (int) party);
                    String socketID = tssConnection.second.getSocket().id();
                    String tssUrl = tssConnection.first.getUrl();
                    String urlStr = tssUrl + "/precompute";
                    URL url = new URL(urlStr);
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Access-Control-Allow-Origin", "*");
                    connection.setRequestProperty("Access-Control-Allow-Methods", "GET, POST");
                    connection.setRequestProperty("Access-Control-Allow-Headers", "Content-Type");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setRequestProperty("x-web3-session-id", TSSClient.sid(session));


                    List<String> endpointStrings = new ArrayList<>();
                    List<TSSEndpoint> endpoints = TSSConnectionInfo.getShared().allEndpoints(session);
                    for (TSSEndpoint endpoint : endpoints) {
                        endpointStrings.add(local_servers ? endpoint.getUrl().replace("10.0.2.2","localhost") : endpoint.getUrl());
                    }
                    endpointStrings.add((int) index, "websocket:" + socketID);

                    LinkedHashMap<String, Object> msg = new LinkedHashMap<>();
                    msg.put("endpoints", endpointStrings);
                    msg.put("session", session);
                    List<Integer> partiesList = new ArrayList<>();
                    for (int j = 0; j < parties; j++) {
                        partiesList.add(j);
                    }
                    msg.put("parties", partiesList);
                    msg.put("player_index", party);
                    msg.put("threshold", parties);
                    msg.put("pubkey", pubKey);
                    msg.put("notifyWebsocketId", socketID);
                    msg.put("sendWebsocket", socketID);
                    msg.put("server_coeffs", serverCoeffs);
                    msg.put("signatures", signatures);

                    String jsonData = new ObjectMapper().writeValueAsString(msg);
                    Gson gson = new Gson();
                    JsonObject data = gson.fromJson(jsonData, JsonObject.class);
                    connection.setDoOutput(true);
                    try (DataOutputStream out = new DataOutputStream(connection.getOutputStream())) {
                        out.write(data.toString().getBytes(StandardCharsets.UTF_8));
                        out.flush();
                    }

                    if (connection.getResponseCode() != 200) {
                        System.out.println("Failed precompute route for " + urlStr);
                    }

                    connection.disconnect();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        if (!setup()) {
            throw new TSSClientError("Failed to setup client");
        }

        try {
            String partyArray = IntStream.range(0, parties).mapToObj(String::valueOf).collect(Collectors.joining(","));
            Counterparties counterparties = new Counterparties(partyArray);
            Precompute result = signer.precompute(counterparties, rng, comm);
            consumed = false;
            EventQueue.shared().addEvent(new Event("precompute_complete", session, (int) index, new Date(), EventType.PRECOMPUTE_COMPLETE));
            return result;
        } catch (DKLSError error) {
            EventQueue.shared().addEvent(new Event("precompute_failed", session, (int) index, new Date(), EventType.PRECOMPUTE_ERROR));
            throw new TSSClientError(error.getMessage());
        }
    }

    public Triple<BigInteger, BigInteger, Byte> sign(String message, boolean hashOnly, String originalMessage,
                                                     Precompute precompute, List<String> signatures) throws TSSClientError {
        try {
            if (!isReady()) {
                throw new TSSClientError("Client is not ready");
            }

            if (consumed) {
                throw new TSSClientError("This instance has already signed a message and cannot be reused");
            }

            int precomputesComplete = EventQueue.shared().countEvents(session).getOrDefault(EventType.PRECOMPUTE_COMPLETE, 0);
            if (precomputesComplete != parties) {
                throw new TSSClientError("Insufficient Precomputes");
            }

            String signingMessage = "";

            if (hashOnly) {
                if (originalMessage != null) {
                    String hashedMessage = bytesToHex(TSSHelpers.hashMessage(originalMessage.getBytes(StandardCharsets.UTF_8)));
                    if (!hashedMessage.equals(message)) {
                        throw new TSSClientError("hash of original message does not match message");
                    }
                    signingMessage = new String(Hex.decode(message.getBytes())); // Assuming Hex class converts from hex to bytes
                } else {
                    throw new TSSClientError("Original message has to be provided");
                }
            } else {
                signingMessage = message;
            }

            List<String> fragments = new ArrayList<>();
            for (int i = 0; i < precomputesComplete; i++) {
                if (i != index) {
                    TSSEndpoint tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, (int) i).first;
                    String urlStr = tssConnection.getUrl() + "/sign";
                    URL url = new URL(urlStr);
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setRequestProperty("x-web3-session-id", TSSClient.sid(session));

                    Map<String, Object> msg = new HashMap<>();
                    msg.put("session", session);
                    msg.put("sender", index);
                    msg.put("recipient", i);
                    msg.put("msg", signingMessage);
                    msg.put("hash_only", hashOnly);
                    msg.put("original_message", originalMessage != null ? originalMessage : "");
                    msg.put("hash_algo", "keccak256");
                    msg.put("signatures", signatures);

                    String jsonData = new ObjectMapper().writeValueAsString(msg);
                    connection.setDoOutput(true);
                    try (DataOutputStream out = new DataOutputStream(connection.getOutputStream())) {
                        out.writeBytes(jsonData);
                        out.flush();
                    }

                    if (connection.getResponseCode() != 200) {
                        System.out.println("Failed send route for " + urlStr);
                    }

                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                        String response = reader.lines().collect(Collectors.joining());
                        Map<String, String> responseMap = new ObjectMapper().readValue(response, new TypeReference<Map<String, String>>() {
                        });
                        String signatureFragment = responseMap.entrySet().iterator().next().getValue();
                        fragments.add(signatureFragment);
                    }

                    connection.disconnect();
                }
            }

            String signatureFragment = signWithPrecompute(signingMessage, hashOnly, precompute);
            fragments.add(signatureFragment);

            String input = String.join(",", fragments);
            SignatureFragments sigFrags = new SignatureFragments(input);

            String signature = verifyWithPrecompute(signingMessage, hashOnly, precompute, sigFrags, pubKey);

            String precompute_r = precompute.getR();
            byte[] decoded_r = Base64.decode(precompute_r);
            byte[] decoded = Base64.decode(signature);
            String sighex = Utils.convertByteToHexadecimal(decoded);
            BigInteger r = new BigInteger(sighex.substring(0, 64), 16);
            BigInteger s = new BigInteger(sighex.substring(64), 16);
            byte recoveryParam = (byte) (decoded_r[decoded_r.length - 1] % 2);

            if (_sLessThanHalf) {
                BigInteger halfOfSecp256k1n = TSSClient.modulusValueSigned.divide(BigInteger.valueOf(2));
                if (s.compareTo(halfOfSecp256k1n) > 0) {
                    s = TSSClient.modulusValueSigned.subtract(s);
                    recoveryParam = (byte) ((recoveryParam + 1) % 2);
                }
            }

            consumed = true;
            return new Triple(s, r, recoveryParam);
        } catch (Exception | DKLSError e) {
            throw new TSSClientError(e.getMessage());
        }
    }


    private String signWithPrecompute(String message, boolean hashOnly, Precompute precompute) throws Exception, DKLSError {
        return Utilities.localSign(message, hashOnly, precompute);
    }

    private String verifyWithPrecompute(String message,  boolean hashOnly, Precompute precompute, SignatureFragments fragments, String pubKey) throws Exception, DKLSError {
        return Utilities.localVerify(message, hashOnly, precompute, fragments, pubKey);
    }

    public boolean isReady() throws TSSClientError {
        // TODO: Add timeout here
        try {
            Map<EventType, Integer> counts = EventQueue.shared().countEvents(session);
            Integer precomputeErrorCount = counts.getOrDefault(EventType.PRECOMPUTE_ERROR, 0);

            if (precomputeErrorCount > 0) {
                throw new TSSClientError("Error occurred during precompute");
            }

            Integer precomputeCompleteCount = counts.getOrDefault(EventType.PRECOMPUTE_COMPLETE, 0);
            assert precomputeCompleteCount != null;
            return precomputeCompleteCount.equals(parties);
        } catch (Exception e) {
            throw new TSSClientError(e.getMessage());
        }
    }

    public boolean checkConnected() {
        // TODO: Add timeout here
        int connections = 0;
        List<Integer> connectedParties = new ArrayList<>();

        for (int party_index = 0; party_index < parties; party_index++) {
            if (party_index != index) {
                if (!connectedParties.contains(party_index)) {
                    try {
                        TSSSocket socketConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, party_index).second;
                        if (socketConnection == null || socketConnection.getSocket() == null) {
                            continue;
                        }
                        if (socketConnection.getSocket().connected() &&
                                socketConnection.getSocket().id() != null) {
                            connections++;
                            connectedParties.add(party_index);
                        }
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            }
        }
        return connections == (parties - 1);
    }

    public void cleanup(String[] signatures) throws Exception {
        MessageQueue.shared().removeMessages(this.session);
        EventQueue.shared().removeEvents(this.session);
        boolean consumed = false;
        boolean ready = false;

        for (int i = 0; i < this.parties; i++) {
            if (i != this.index) {
                Pair<TSSEndpoint, TSSSocket> tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(this.session, i);
                String url = tssConnection.first.getUrl();
                URL endpoint = new URL(url + "/cleanup");
                HttpURLConnection connection = (HttpURLConnection) endpoint.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Access-Control-Allow-Origin", "*");
                connection.setRequestProperty("Access-Control-Allow-Methods", "GET, POST");
                connection.setRequestProperty("Access-Control-Allow-Headers", "Content-Type");
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setRequestProperty("x-web3-session-id", TSSClient.sid(session));

                Map<String, Object> msg = new HashMap<>();
                msg.put("session", session);
                msg.put("signatures", signatures);

                connection.setDoOutput(true);
                OutputStream out = connection.getOutputStream();
                out.write(new ObjectMapper().writeValueAsBytes(msg));

                int responseCode = connection.getResponseCode();
                if (responseCode != 200) {
                    System.out.println("Failed to cleanup for " + url);
                }

                connection.disconnect();
            }
        }
    }
}
