package com.web3auth.tss_client_android;

import androidx.core.util.Pair;

import com.google.gson.Gson;
import com.web3auth.tss_client_android.client.SECP256K1;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.dkls.DKLSError;
import com.web3auth.tss_client_android.dkls.Precompute;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import kotlin.Triple;

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

    private List<String> getSignatures() throws IOException {
        Map<String, Object> tokenData = new HashMap<>();
        tokenData.put("exp", new Date().getTime() + 3000 * 60);
        tokenData.put("temp_key_x", "test_key_x");
        tokenData.put("temp_key_y", "test_key_y");
        tokenData.put("verifier_name", "test_verifier_name");
        tokenData.put("verifier_id", "test_verifier_id");

        String token = Base64.getEncoder().encodeToString(gson.toJson(tokenData).getBytes());

        List<String> sigs = new ArrayList<>();
        for (String privKey : getPrivateKeys()) {
            byte[] hash = TSSHelpers.hashMessage(token.getBytes(StandardCharsets.UTF_8));
            Sign.SignatureData signature = Sign.signPrefixedMessage(hash, ECKeyPair.create(privKey.getBytes(StandardCharsets.UTF_8)));
            String sig = signature.getR().toString() + signature.getR().toString()
                    + String.format("%02X", signature.getV());
            Map<String, Object> msg = new HashMap<>();
            msg.put("data", token);
            msg.put("sig", sig);
            String jsonData = gson.toJson(msg);
            sigs.add(jsonData);
        }

        return sigs;
    }

    public static void distributeShares(BigInteger privKey, List<Integer> parties, List<String> endpoints,
                                        int localClientIndex, String session) throws IOException {
        List<BigInteger> additiveShares = new ArrayList<>();
        BigInteger shareSum = BigInteger.ZERO;
        int numParties = parties.size();

        for (int i = 0; i < numParties - 1; i++) {
            BigInteger shareBigUint = new BigInteger(256, new java.security.SecureRandom());
            BigInteger shareBigInt = shareBigUint;
            additiveShares.add(shareBigInt);
            shareSum = shareSum.add(shareBigInt);
        }

        BigInteger finalShare = privKey.subtract(shareSum).mod(TSSClient.modulusValueSigned);
        additiveShares.add(finalShare);

        BigInteger reduced = additiveShares.stream().reduce(BigInteger.ZERO, BigInteger::add).mod(TSSClient.modulusValueSigned);
        if (reduced.equals(privKey)) {
            System.out.println("Reduction successful!");
        } else {
            System.out.println("Reduction failed.");
        }

        // denormalize shares
        List<BigInteger> shares = new ArrayList<>();
        for (int i = 0; i < numParties; i++) {
            BigInteger additiveShare = additiveShares.get(i);
            List<BigInteger> partiesBigInt = new ArrayList<>();
            for (Integer party : parties) {
                partiesBigInt.add(new BigInteger(party.toString()));
            }
            BigInteger denormalizedShare = denormalizeShare(additiveShare, partiesBigInt, BigInteger.valueOf(i));
            shares.add(denormalizedShare);
        }

        for (int i = 0; i < numParties; i++) {
            BigInteger share = shares.get(i);
            if (i == localClientIndex) {
                // Set the share and session for the local client.
                // Note: Replace this with the actual logic for setting the share and session.
                // For example:
                // this.share = share;
                // this.session = session;
                System.out.println("Local client share: " + share);
                System.out.println("Local client session: " + session);
            } else {
                // Send the share to other parties using HTTP POST requests.
                String endpoint = endpoints.get(i);
                URL url = new URL(endpoint + "/share");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("x-web3-session-id", session);

                String json = "{\"session\":\"" + session + "\",\"share\":\"" + share.toString() + "\"}";
                byte[] postData = json.getBytes(StandardCharsets.UTF_8);

                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(postData);
                }

                int responseCode = conn.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    System.out.println("Share sent successfully to party " + i);
                } else {
                    System.out.println("Failed to send share to party " + i + ", response code: " + responseCode);
                }

                conn.disconnect();
            }
        }
    }

    private static Pair<BigInteger, BigInteger> setupMockShares(List<String> endpoints, List<Integer> parties, int localClientIndex, String session) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        BigInteger privKey = SECP256K1.generatePrivateKey();
        BigInteger publicKey = SECP256K1.privateToPublic(privKey.toString(16));

        distributeShares(privKey, parties, endpoints, localClientIndex, session);
        return new Pair(privKey, publicKey);
    }

    private static EndpointsData generateEndpoints(int parties, int clientIndex) {
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
        return new EndpointsData(endPoints, tssWSEndpoints, partyIndexes);
    }

    private static BigInteger denormalizeShare(BigInteger additiveShare, List<BigInteger> parties, BigInteger party) {
        BigInteger coeff = TSSHelpers.getLagrangeCoefficients(parties.toArray(new BigInteger[]{}), party);
        BigInteger coeffInverse = coeff.modInverse(TSSClient.modulusValueSigned);
        return additiveShare.multiply(coeffInverse).mod(TSSClient.modulusValueSigned);
    }

    @Test
    public void testExample() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, DKLSError {
        int parties = 4;
        String msg = "hello world";
        byte[] msgHash = TSSHelpers.hashMessage(msg.getBytes(StandardCharsets.UTF_8));
        int clientIndex = parties - 1;

        BigInteger randomKey = SECP256K1.generatePrivateKey();
        BigInteger random = randomKey.add(BigInteger.valueOf(System.currentTimeMillis() / 1000));
        byte[] randomNonce = TSSHelpers.hashMessage(random.toByteArray());
        String testingRouteIdentifier = "testingShares";
        String vid = "test_verifier_name" + Delimiters.Delimiter1 + "test_verifier_id";
        String session = testingRouteIdentifier +
                vid + Delimiters.Delimiter2 + "default" + Delimiters.Delimiter3 + "0" + Delimiters.Delimiter4 +
                Hex.toHexString(randomNonce) + testingRouteIdentifier;
        List<String> sigs = new ArrayList<>();//getSignatures();
        sigs.add("abc");
        sigs.add("asd");
        EndpointsData endpointsResult = Utils.generateEndpoints(parties, clientIndex);
        List<String> endpoints = endpointsResult.getEndpoints();
        List<String> socketEndpoints = endpointsResult.getTssWSEndpoints();
        List<Integer> partyIndexes = endpointsResult.getPartyIndexes();

        Pair<BigInteger, BigInteger> shareRes = setupMockShares(endpoints, partyIndexes, clientIndex, session);
        BigInteger privateKey = shareRes.first;
        BigInteger publicKey = shareRes.second;

        Map<String, String> coeffs = new HashMap<>();
        int[] participatingServerDKGIndexes = {1, 2, 3};
        for (int i = 0; i < participatingServerDKGIndexes.length; i++) {
            BigInteger coeff = BigInteger.ONE; // Initialize to 1
            byte[] serializedCoeff = coeff.toByteArray(); // Serialize the BigInteger
            byte[] suffix = new byte[Math.min(32, serializedCoeff.length)];
            System.arraycopy(serializedCoeff, Math.max(0, serializedCoeff.length - 32), suffix, 0, suffix.length);
            String hexString = TSSHelpers.byteArrayToHexString(suffix);
            coeffs.put(String.valueOf(i), hexString);
        }

        TSSClient client = null;
        try {
            client = new TSSClient(session, clientIndex, partyIndexes.stream().mapToInt(Integer::intValue).toArray(),
                    endpoints.toArray(new String[0]), socketEndpoints.toArray(new String[0]),
                    TSSHelpers.base64Share(share), TSSHelpers.base64PublicKey(publicKey.toByteArray()));
            while (!client.checkConnected()) {
                // no-op
            }
            Precompute precompute = client.precompute(coeffs, sigs);
            while (!client.isReady()) {
                // no-op
            }

            Triple signatureResult = client.sign(TSSHelpers.bytesToHex(msgHash), true, msg, precompute, sigs);
            client.cleanup(sigs.toArray(new String[0]));
            String pubKey = TSSHelpers.recoverPublicKey(TSSHelpers.bytesToHex(msgHash), (BigInteger) signatureResult.getFirst(),
                    (BigInteger) signatureResult.getSecond(), (Byte) signatureResult.getThird());
            String pkHex65 = pubKey;
            BigInteger skToPkHex = SECP256K1.privateToPublic(privateKey.toString(16));
            System.out.println(pkHex65.equals(skToPkHex.toString(16)));

            System.out.println("Signature (hex): " + TSSHelpers.hexSignature((BigInteger) signatureResult.getFirst(),
                    (BigInteger) signatureResult.getSecond(), (Byte) signatureResult.getThird()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
