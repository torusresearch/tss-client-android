package com.web3auth.tss_client_android;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import io.socket.client.IO;
import io.socket.client.Socket;

public class Utils {

    private static final SecureRandom secureRandom = new SecureRandom();
    public static final BigInteger secp256k1N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public static List<String> torusNodeEndpoints = Arrays.asList(
            "https://sapphire-1.auth.network/sss/jrpc",
            "https://sapphire-2.auth.network/sss/jrpc",
            "https://sapphire-3.auth.network/sss/jrpc",
            "https://sapphire-4.auth.network/sss/jrpc",
            "https://sapphire-5.auth.network/sss/jrpc"
    );

    public static ECNamedCurveParameterSpec getEC() {
        return ECNamedCurveTable.getParameterSpec("secp256k1");
    }

    /*public static BigInteger getLagrangeCoeffs(BigInteger[] shares, BigInteger[] nodeIndex) {
        if (shares.length != nodeIndex.length) {
            return null;
        }
        BigInteger secret = new BigInteger("0");
        for (int i = 0; i < shares.length; i++) {
            BigInteger upper = new BigInteger("1");
            BigInteger lower = new BigInteger("1");
            for (int j = 0; j < shares.length; j++) {
                if (i != j) {
                    upper = upper.multiply(nodeIndex[j].negate());
                    upper = upper.mod(secp256k1N);
                    BigInteger temp = nodeIndex[i].subtract(nodeIndex[j]);
                    temp = temp.mod(secp256k1N);
                    lower = lower.multiply(temp).mod(secp256k1N);
                }
            }
            BigInteger delta = upper.multiply(lower.modInverse(secp256k1N)).mod(secp256k1N);
            delta = delta.multiply(shares[i]).mod(secp256k1N);
            secret = secret.add(delta);
        }
        return secret.mod(secp256k1N);
    }*/

    public static BigInteger getLagrangeCoeffs(BigInteger[] allIndexes, BigInteger myIndex) {
        BigInteger target = new BigInteger("0");
        BigInteger upper = new BigInteger("1");
        BigInteger lower = new BigInteger("1");
        for (BigInteger index : allIndexes) {
            if (myIndex.compareTo(index) != 0) {
                BigInteger tempUpper = target.subtract(index).mod(secp256k1N);
                upper = upper.multiply(tempUpper).mod(secp256k1N);

                BigInteger tempLower = myIndex.subtract(index).mod(secp256k1N);
                lower = lower.multiply(tempLower).mod(secp256k1N);
            }
        }
        BigInteger invLower = lower.modInverse(secp256k1N);
        return upper.multiply(invLower).mod(secp256k1N);
    }

    public static String padLeft(String inputString, Character padChar, int length) {
        if (inputString.length() >= length) return inputString;
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append(padChar);
        }
        sb.append(inputString);
        return sb.toString();
    }

    public static ECPoint ecPoint(String x, String y) {
        return getEC().getCurve().createPoint(new BigInteger(Utils.padLeft(x, '0', 64), 16),
                new BigInteger(Utils.padLeft(y, '0', 64), 16));
    }

    public static BigInteger getAdditiveCoeff(boolean isUser, BigInteger[] participatingServerIndexes, BigInteger userTSSIndex, BigInteger serverIndex) {
        if (isUser) {
            return getLagrangeCoeffs(new BigInteger[]{new BigInteger("1"), userTSSIndex}, userTSSIndex);
        }
        BigInteger serverLagrangeCoeff = getLagrangeCoeffs(participatingServerIndexes, serverIndex);
        BigInteger masterLagrangeCoeff = getLagrangeCoeffs(new BigInteger[]{new BigInteger("1"), userTSSIndex}, new BigInteger("1"));
        BigInteger additiveLagrangeCoeff = serverLagrangeCoeff.multiply(masterLagrangeCoeff).mod(secp256k1N);
        System.out.println("Additive Coeff: " + additiveLagrangeCoeff);
        return additiveLagrangeCoeff;
    }

    public static BigInteger getDenormaliseCoeff(BigInteger party, List<BigInteger> parties) {
        if (!parties.contains(party)) {
            throw new IllegalArgumentException("party " + party + " not found in parties " + parties);
        }

        return getLagrangeCoeffs(parties.toArray(new BigInteger[0]), party).modInverse(secp256k1N);
    }

    public static BigInteger getDKLSCoeff(boolean isUser, List<BigInteger> participatingServerIndexes,
                                          BigInteger userTSSIndex, BigInteger serverIndex) {
        List<BigInteger> sortedServerIndexes = new ArrayList<>(participatingServerIndexes);
        Collections.sort(sortedServerIndexes);

        for (int i = 0; i < sortedServerIndexes.size(); i++) {
            if (!Objects.equals(sortedServerIndexes.get(i), participatingServerIndexes.get(i))) {
                throw new IllegalArgumentException("server indexes must be sorted");
            }
        }

        List<BigInteger> parties = new ArrayList<>();

        // total number of parties for DKLS = total number of servers + 1 (user is the last party)
        // server party indexes
        int serverPartyIndex = 0;
        for (int i = 0; i < participatingServerIndexes.size(); i++) {
            int currentPartyIndex = i + 1;
            parties.add(BigInteger.valueOf(currentPartyIndex));
            if (Objects.equals(participatingServerIndexes.get(i), serverIndex)) {
                serverPartyIndex = currentPartyIndex;
            }
        }
        BigInteger userPartyIndex = BigInteger.valueOf(parties.size() + 1);
        parties.add(userPartyIndex); // user party index

        BigInteger coeff;
        if (isUser) {
            BigInteger additiveCoeff = getAdditiveCoeff(true, participatingServerIndexes.toArray(new BigInteger[0]), userTSSIndex, serverIndex);
            BigInteger denormaliseCoeff = getDenormaliseCoeff(userPartyIndex, parties);
            return denormaliseCoeff.multiply(additiveCoeff).mod(secp256k1N);
        }

        BigInteger additiveCoeff = getAdditiveCoeff(false, participatingServerIndexes.toArray(new BigInteger[0]), userTSSIndex, serverIndex);
        BigInteger denormaliseCoeff = getDenormaliseCoeff(BigInteger.valueOf(serverPartyIndex), parties);
        coeff = denormaliseCoeff.multiply(additiveCoeff).mod(secp256k1N);
        return coeff;
    }

    public static ECPoint getTSSPubKey(Key dkgPubKey, Key userSharePubKey, BigInteger userTSSIndex) {
        BigInteger serverLagrangeCoeff = getLagrangeCoeffs(new BigInteger[]{new BigInteger("1"), userTSSIndex}, new BigInteger("1"));
        BigInteger userLagrangeCoeff = getLagrangeCoeffs(new BigInteger[]{new BigInteger("1"), userTSSIndex}, userTSSIndex);

        ECPoint serverTerm = ecPoint(dkgPubKey.getX(), dkgPubKey.getY()).multiply(serverLagrangeCoeff);
        ECPoint userTerm = ecPoint(userSharePubKey.getX(), userSharePubKey.getY()).multiply(userLagrangeCoeff);
        return serverTerm.add(userTerm);
    }

    public static EndpointsData generateEndpoints(int parties, int clientIndex) {
        List<String> endpoints = new ArrayList<>();
        List<String> tssWSEndpoints = new ArrayList<>();
        List<Integer> partyIndexes = new ArrayList<>();
        for (int i = 0; i < parties; i++) {
            partyIndexes.add(i);
            if (i == clientIndex) {
                endpoints.add(null);
                tssWSEndpoints.add(null);
            } else {
                endpoints.add("https://sapphire-" + (i + 1) + ".auth.network/tss");
                tssWSEndpoints.add("https://sapphire-" + (i + 1) + ".auth.network");
            }
        }
        return new EndpointsData(endpoints, tssWSEndpoints, partyIndexes);
    }

    public static List<Socket> createSockets(List<String> wsEndpoints, String sessionId) throws URISyntaxException {
        List<Socket> sockets = new ArrayList<>();
        for (String wsEndpoint : wsEndpoints) {
            if (wsEndpoint == null) {
                sockets.add(null);
                return sockets;
            }
            IO.Options options = new IO.Options();
            options.path = "/tss/socket.io";
            options.query = sessionId;
            options.transports = new String[]{"websocket"};
            options.secure = true;
            options.reconnectionDelayMax = 10000;
            options.reconnectionAttempts = 3;
            sockets.add(IO.socket(wsEndpoint, options));
        }
        return sockets;
    }

    public static CompletableFuture<List<Socket>> setupSockets(List<String> wsEndpoints, String sessionId) throws URISyntaxException {
        List<Socket> sockets = createSockets(wsEndpoints, sessionId);
        ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();
        CompletableFuture<Void> allConnectionsFuture = new CompletableFuture<>();
        executorService.scheduleAtFixedRate(() -> {
            boolean allConnected = true;
            for (Socket socket : sockets) {
                if (socket != null && !socket.connected()) {
                    allConnected = false;
                    break;
                }
            }
            if (allConnected) {
                executorService.shutdown();
                allConnectionsFuture.complete(null);
            }
        }, 0, 100, TimeUnit.MILLISECONDS);

        return CompletableFuture.allOf(allConnectionsFuture)
                .thenApply(v -> sockets);
    }

    public static String convertByteToHexadecimal(byte[] byteArray) {
        StringBuilder hex = new StringBuilder();
        for (byte i : byteArray) {
            hex.append(String.format("%02X", i));
        }
        return hex.toString();
    }

    public static void ClearBytes(byte[] data) {
        Arrays.fill(data, (byte) 0);
    }

    public static SecureRandom SecureRandom() {
        return secureRandom;
    }

    public static byte[] RandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
