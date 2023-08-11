package com.web3auth.tss_client_android;

import static org.junit.Assert.assertEquals;

import androidx.core.util.Pair;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.web3auth.tss_client_android.client.SECP256K1;
import com.web3auth.tss_client_android.client.TSSClient;
import com.web3auth.tss_client_android.client.TSSHelpers;
import com.web3auth.tss_client_android.dkls.DKLSError;
import com.web3auth.tss_client_android.dkls.Precompute;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
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

    private static String session = "";
    private static BigInteger share = new BigInteger("0");
    private Gson gson = new Gson();

    @BeforeClass
    public static void setupTest() {
        SECP256K1.setupBouncyCastle();
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
            Sign.SignatureData signature = Sign.signPrefixedMessage(hash, ECKeyPair.create(hexStringToByteArray(privKey)));
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(signature.getR()));
            v.add(new ASN1Integer(signature.getS()));
            DERSequence der = new DERSequence(v);
            byte[] sigBytes = der.getEncoded();
            String sig = Utils.convertByteToHexadecimal(sigBytes);
            Map<String, Object> msg = new HashMap<>();
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
                upper = upper.multiply(otherPartyIndexNeg).mod(SECP256K1.modulusValueSigned);
                BigInteger temp = partyIndex.subtract(otherPartyIndex).mod(SECP256K1.modulusValueSigned);
                lower = lower.multiply(temp).mod(SECP256K1.modulusValueSigned);
            }
        }

        BigInteger lowerInverse = lower.modInverse(SECP256K1.modulusValueSigned);
        BigInteger delta = upper.multiply(lowerInverse).mod(SECP256K1.modulusValueSigned);
        return delta;
    }

    public static void distributeShares(BigInteger privKey, List<Integer> parties, List<String> endpoints,
                                        int localClientIndex, String _session) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InterruptedException {
        List<BigInteger> additiveShares = new ArrayList<>();
        BigInteger shareSum = BigInteger.ZERO;

        for (int i = 0; i < parties.size() - 1; i++) {
            byte[] shareBytes = SECP256K1.generatePrivateKey().toByteArray();
            BigInteger shareBigInt = new BigInteger(1, shareBytes);
            additiveShares.add(shareBigInt);
            shareSum = shareSum.add(shareBigInt);
        }

        BigInteger finalShare = privKey.subtract(shareSum.mod(SECP256K1.modulusValueSigned))
                .mod(SECP256K1.modulusValueSigned);
        additiveShares.add(finalShare);

        BigInteger reduced = additiveShares.stream().reduce(BigInteger.ZERO, BigInteger::add)
                .mod(SECP256K1.modulusValueSigned);
        Assert.assertEquals(reduced.toString(16), privKey.toString(16));

        List<BigInteger> shares = new ArrayList<>();
        for (int i = 0; i < additiveShares.size(); i++) {
            BigInteger additiveShare = additiveShares.get(i);
            BigInteger[] partiesBigInt = new BigInteger[parties.size()];
            for (int j = 0; j < parties.size(); j++) {
                partiesBigInt[j] = BigInteger.valueOf(parties.get(j));
            }

            BigInteger coeffInverse = lagrange(partiesBigInt, BigInteger.valueOf(i)).modInverse(SECP256K1.modulusValueSigned);
            BigInteger denormalizedShare = additiveShare.multiply(coeffInverse).mod(SECP256K1.modulusValueSigned);
            shares.add(denormalizedShare);
        }

        CountDownLatch latch = new CountDownLatch(parties.size() - 1);

        for (int i = 0; i < parties.size(); i++) {
            BigInteger _share = shares.get(i);

            if (i == localClientIndex) {
                share = _share;
                session = _session;
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
                            conn.setRequestProperty("x-web3-session-id", TSSClient.sid(session));

                            String json = "{\"session\":\"" + session + "\",\"share\":\"" + share.toString() + "\"}";
                            Gson gson = new Gson();
                            JsonObject data = gson.fromJson(json, JsonObject.class);
                            conn.setDoOutput(true);
                            try (OutputStream os = conn.getOutputStream()) {
                                os.write(data.toString().getBytes(StandardCharsets.UTF_8));
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
                endPoints.add("http://192.168.1.11:" + (basePort + serverPortOffset));
                tssWSEndpoints.add("http://192.168.1.11:" + (basePort + serverPortOffset));
                serverPortOffset++;
            }
        }
        return new EndpointsData(endPoints, tssWSEndpoints, partyIndexes);
    }

    @Test
    public void testExample() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, DKLSError, InterruptedException {
        int parties = 4;
        String msg = "hello world";
        byte[] msgHash = TSSHelpers.hashMessage(msg.getBytes(StandardCharsets.UTF_8));
        int clientIndex = parties - 1;

        BigInteger randomKey = SECP256K1.generatePrivateKey();
        BigInteger random = randomKey.add(BigInteger.valueOf(System.currentTimeMillis() / 1000));
        String randomNonce = TSSHelpers.bytesToHex(TSSHelpers.hashMessage(random.toByteArray()));
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

        TSSClient client;
        try {
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

            Triple<BigInteger, BigInteger, Byte> signatureResult = client.sign(TSSHelpers.bytesToHex(msgHash), true, msg, precompute, sigs);
            client.cleanup(sigs.toArray(new String[0]));
            assert TSSHelpers.verifySignature(TSSHelpers.bytesToHex(msgHash), signatureResult.getFirst(),
                    signatureResult.getSecond(), signatureResult.getThird(), publicKey.toByteArray());
            String pubKey = TSSHelpers.recoverPublicKey(TSSHelpers.bytesToHex(msgHash), signatureResult.getFirst(),
                    signatureResult.getSecond(), signatureResult.getThird());
            String pkHex65 = pubKey;
            BigInteger skToPkHex = SECP256K1.privateToPublic(privateKey.toString(16));
            assertEquals(pkHex65, skToPkHex.toString(16));
            System.out.println(pkHex65.equals(skToPkHex.toString(16)));

            System.out.println("Signature (hex): " + TSSHelpers.hexSignature(signatureResult.getFirst(),
                    signatureResult.getSecond(), signatureResult.getThird()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
