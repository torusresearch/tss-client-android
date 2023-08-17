package com.web3auth.tss_client_android;

import static org.junit.Assert.assertEquals;

import androidx.core.util.Pair;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.google.gson.Gson;
import com.web3auth.tss_client_android.client.EndpointsData;
import com.web3auth.tss_client_android.client.util.Secp256k1;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.dkls.DKLSError;
import com.web3auth.tss_client_android.dkls.Precompute;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

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
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import kotlin.Triple;

@RunWith(AndroidJUnit4.class)
public class TssClientTests {

    static {
        System.loadLibrary("dkls-native");
    }

    static class Delimiters {
        public static final String Delimiter1 = "\u001c";
        public static final String Delimiter2 = "\u0015";
        public static final String Delimiter3 = "\u0016";
        public static final String Delimiter4 = "\u0017";
    }

    private final List<String> privateKeys = new ArrayList<>();
    private static BigInteger share = new BigInteger("0");
    private final Gson gson = new Gson();

    @BeforeClass
    public static void setupTest() {
        System.setProperty("LOCAL_SERVERS", String.valueOf(true));
    }

    @AfterClass
    public static void cleanTest() {
        System.gc();
    }

    private List<String> getPrivateKeys() {
        privateKeys.add("da4841d60f47652584aea0ab578660b353dbcd6907940ed0a295c9d95aabadd0");
        privateKeys.add("e7ef4a9dcc9c0305ec9e56c79128f5c12413b976309368c35c11f3297459994b");
        privateKeys.add("31534072a75a1d8b7f07c1f29930533ae44166f44ce08a4a23126b6dcb8b6efe");
        privateKeys.add("f2588097a5df3911e4826e13dce2b6f4afb798bb8756675b17d4195db900af20");
        privateKeys.add("5513438cd00c901ff362e25ae08aa723495bea89ab5a53ce165730bc1d9a0280");
        return privateKeys;
    }

    private List<String> getSignatures() {
        LinkedHashMap<String, Object> tokenData = new LinkedHashMap<>();
        tokenData.put("exp", new Date().getTime() + 3000 * 60);
        tokenData.put("temp_key_x", "test_key_x");
        tokenData.put("temp_key_y", "test_key_y");
        tokenData.put("verifier_name", "test_verifier_name");
        tokenData.put("verifier_id", "test_verifier_id");

        String token = android.util.Base64.encodeToString(gson.toJson(tokenData).getBytes(StandardCharsets.UTF_8),android.util.Base64.NO_WRAP);

        List<String> sigs = new ArrayList<>();
        for (String privKey : getPrivateKeys()) {
            String hash = TSSHelpers.hashMessage(token);
            byte[] b64encodedData = android.util.Base64.decode(hash, android.util.Base64.NO_WRAP);
            Secp256k1.ECDSASignature ecdsaSignature = Secp256k1.Sign(b64encodedData, hexStringToByteArray(privKey));
            String sig = ecdsaSignature.r.toString(16) +  ecdsaSignature.s.toString(16) + String.format("%02X", ecdsaSignature.v);
            LinkedHashMap<String, Object> msg = new LinkedHashMap<>();
            msg.put("data", token);
            msg.put("sig", sig);
            String jsonData = gson.toJson(msg);
            sigs.add(jsonData);
        }

        return sigs;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }

    public static BigInteger lagrange(BigInteger[] parties, BigInteger party) {
        BigInteger partyIndex = party.add(BigInteger.ONE);
        BigInteger upper = BigInteger.ONE;
        BigInteger lower = BigInteger.ONE;

        for (BigInteger otherParty : parties) {
            BigInteger otherPartyIndex = otherParty.add(BigInteger.ONE);

            if (!party.equals(otherParty)) {
                BigInteger otherPartyIndexNeg = otherPartyIndex.negate();
                upper = upper.multiply(otherPartyIndexNeg).mod(Secp256k1.CURVE.getN());
                BigInteger temp = partyIndex.subtract(otherPartyIndex).mod(Secp256k1.CURVE.getN());
                lower = lower.multiply(temp).mod(Secp256k1.CURVE.getN());
            }
        }

        BigInteger lowerInverse = lower.modInverse(Secp256k1.CURVE.getN());
        BigInteger delta = upper.multiply(lowerInverse).mod(Secp256k1.CURVE.getN());
        return delta;
    }

    public static void distributeShares(BigInteger privKey, List<Integer> parties, List<String> endpoints,
                                        int localClientIndex, String _session) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InterruptedException {
        List<BigInteger> additiveShares = new ArrayList<>();
        BigInteger shareSum = BigInteger.ZERO;

        for (int i = 0; i < parties.size() - 1; i++) {
            byte[] shareBytes = Secp256k1.GenerateECKey();
            BigInteger shareBigInt = new BigInteger(1, shareBytes);
            additiveShares.add(shareBigInt);
            shareSum = shareSum.add(shareBigInt);
        }

        BigInteger finalShare = privKey.subtract(shareSum.mod(Secp256k1.CURVE.getN()))
                .mod(Secp256k1.CURVE.getN());
        additiveShares.add(finalShare);

        BigInteger reduced = additiveShares.stream().reduce(BigInteger.ZERO, BigInteger::add)
                .mod(Secp256k1.CURVE.getN());
        Assert.assertEquals(reduced.toString(16), privKey.toString(16));

        List<BigInteger> shares = new ArrayList<>();
        for (int i = 0; i < additiveShares.size(); i++) {
            BigInteger additiveShare = additiveShares.get(i);
            BigInteger[] partiesBigInt = new BigInteger[parties.size()];
            for (int j = 0; j < parties.size(); j++) {
                partiesBigInt[j] = BigInteger.valueOf(parties.get(j));
            }

            BigInteger coeffInverse = lagrange(partiesBigInt, BigInteger.valueOf(i)).modInverse(Secp256k1.CURVE.getN());
            BigInteger denormalizedShare = additiveShare.multiply(coeffInverse).mod(Secp256k1.CURVE.getN());
            shares.add(denormalizedShare);
        }

        CountDownLatch latch = new CountDownLatch(parties.size() - 1);

        for (int i = 0; i < parties.size(); i++) {
            BigInteger _share = shares.get(i);

            if (i == localClientIndex) {
                share = _share;
            } else {
                String endpoint = endpoints.get(i);
                if (endpoint != null) {
                    int finalI = i;
                    Thread thread = new Thread(() -> {
                        try {
                            URL url = new URL(endpoint + "/share");
                            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                            conn.setRequestMethod("POST");
                            conn.setRequestProperty("Content-Type", "application/json");
                            conn.setRequestProperty("x-web3-session-id", TSSClient.sid(_session));

                            String b64Share = android.util.Base64.encodeToString(share.toByteArray(), android.util.Base64.NO_WRAP);
                            LinkedHashMap<String, Object> msg = new LinkedHashMap<>();
                            msg.put("session", _session);
                            msg.put("share", b64Share);

                            Gson gson = new Gson();
                            byte[] data = gson.toJson(msg).getBytes(StandardCharsets.UTF_8);
                            conn.setDoOutput(true);
                            try (OutputStream os = conn.getOutputStream()) {
                                os.write(data);
                            }

                            int responseCode = conn.getResponseCode();
                            if (responseCode == HttpURLConnection.HTTP_OK) {
                                System.out.println("Share sent successfully to party " + finalI);
                            } else {
                                System.out.println("Failed to send share to party " + finalI + ", response code: " + responseCode);
                            }

                            conn.disconnect();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        } finally {
                            latch.countDown();
                        }
                    });
                    thread.start();
                }
            }
        }

        // Wait for all threads to finish
        latch.await(30, TimeUnit.SECONDS);
    }

    private static Pair<BigInteger, BigInteger> setupMockShares(List<String> endpoints, List<Integer> parties, int localClientIndex, String session) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InterruptedException {
        byte[] pk = Secp256k1.GenerateECKey();
        BigInteger privKey = new BigInteger(1, pk);
        BigInteger publicKey = new BigInteger(Secp256k1.PublicFromPrivateKey(pk));

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
                // https://developer.android.com/studio/run/emulator-networking.html
                endPoints.add("http://10.0.2.2:" + (basePort + serverPortOffset));
                tssWSEndpoints.add("http://10.0.2.2:" + (basePort + serverPortOffset));
                serverPortOffset++;
            }
        }
        return new EndpointsData(endPoints, tssWSEndpoints, partyIndexes);
    }

    @Test
    public void testExample() throws Exception, DKLSError {
        int parties = 4;
        String msg = "hello world";
        String msgHash = TSSHelpers.hashMessage(msg);
        int clientIndex = parties - 1;

        BigInteger randomKey = new BigInteger(1, Secp256k1.GenerateECKey());
        BigInteger random = randomKey.add(BigInteger.valueOf(System.currentTimeMillis() / 1000));
        String randomNonce = TSSHelpers.hashMessage(random.toString(16));
        String testingRouteIdentifier = "testingShares";
        String vid = "test_verifier_name" + Delimiters.Delimiter1 + "test_verifier_id";
        String session = testingRouteIdentifier +
                vid + Delimiters.Delimiter2 + "default" + Delimiters.Delimiter3 + "0"+  Delimiters.Delimiter4 + randomNonce +
                testingRouteIdentifier;
        System.out.println("session:" + session);
        List<String> sigs = getSignatures();
        EndpointsData endpointsResult = generateEndpoints(parties, clientIndex);
        List<String> endpoints = endpointsResult.getEndpoints();
        List<String> socketEndpoints = endpointsResult.getTssWSEndpoints();
        List<Integer> partyIndexes = endpointsResult.getPartyIndexes();

        Pair<BigInteger, BigInteger> shareRes = setupMockShares(endpoints, partyIndexes, clientIndex, session);
        BigInteger privateKey = shareRes.first;
        BigInteger publicKey = shareRes.second;

        LinkedHashMap<String, String> coeffs = new LinkedHashMap<>();
        int[] participatingServerDKGIndexes = {1, 2, 3};
        for (int i = 0; i <= participatingServerDKGIndexes.length; i++) {
            BigInteger coeff = BigInteger.ONE; // Initialize to 1
            byte[] serializedCoeff = coeff.toByteArray(); // Serialize the BigInteger
            byte[] suffix = new byte[Math.min(32, serializedCoeff.length)];
            System.arraycopy(serializedCoeff, Math.max(0, serializedCoeff.length - 32), suffix, 0, suffix.length);
            String hexString = TSSHelpers.byteArrayToHexString(suffix);
            coeffs.put(String.valueOf(i), hexString);
        }

        TSSClient client;
       // try {
            client = new TSSClient(session, clientIndex, partyIndexes.stream().mapToInt(Integer::intValue).toArray(),
                    endpoints.toArray(new String[0]), socketEndpoints.toArray(new String[0]),
                    TSSHelpers.base64Share(share), TSSHelpers.base64PublicKey(publicKey.toByteArray()));
            while (!client.checkConnected()) {
                // no-op
            }
            System.out.println("Reached here");
            Precompute precompute = client.precompute(coeffs, sigs);
            while (!client.isReady()) {
                // no-op
            }

            Triple<BigInteger, BigInteger, Byte> signatureResult = client.sign(msgHash, true, msg, precompute, sigs);
            client.cleanup(sigs.toArray(new String[0]));
            assert TSSHelpers.verifySignature(msgHash, signatureResult.getFirst(),
                    signatureResult.getSecond(), signatureResult.getThird(), publicKey.toByteArray());
            String pubKey = TSSHelpers.recoverPublicKey(msgHash, signatureResult.getFirst(),
                    signatureResult.getSecond(), signatureResult.getThird());
            String pkHex65 = pubKey;
            BigInteger skToPkHex = new BigInteger(Secp256k1.PublicFromPrivateKey(privateKey.toByteArray()));
            assertEquals(pkHex65, skToPkHex.toString(16));
            System.out.println(pkHex65.equals(skToPkHex.toString(16)));

            System.out.println("Signature (hex): " + TSSHelpers.hexSignature(signatureResult.getFirst(),
                    signatureResult.getSecond(), signatureResult.getThird()));
       // } catch (Exception e) {
        //    e.printStackTrace();
       // }
    }
}
