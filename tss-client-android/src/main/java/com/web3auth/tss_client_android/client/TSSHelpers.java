package com.web3auth.tss_client_android.client;

import com.web3auth.tss_client_android.DELIMITERS;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TSSHelpers {

    public static final BigInteger secp256k1N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private TSSHelpers() {
        // Optional: Add any initialization code here
    }

    public static byte[] hashMessage(byte[] message) {
        byte[] hashedData = Hash.sha3(message);
        return hashedData;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String base64Share(BigInteger share) throws TSSClientError {
        if (share.signum() == -1) {
            throw new TSSClientError("Share may not be negative");
        }

        // Convert BigInteger to byte array and take the last 32 bytes
        byte[] shareBytes = share.toByteArray();
        byte[] last32Bytes = new byte[32];
        int length = Math.min(shareBytes.length, 32);
        System.arraycopy(shareBytes, Math.max(0, shareBytes.length - 32), last32Bytes, 0, length);

        // Base64 encode the last 32 bytes
        return android.util.Base64.encodeToString(last32Bytes, android.util.Base64.DEFAULT);
    }

    public static String base64PublicKey(byte[] pubKey) throws TSSClientError {
        if (pubKey.length == 65) {
            if (pubKey[0] == 0) {
                byte[] trimmedKey = new byte[pubKey.length - 1];
                System.arraycopy(pubKey, 1, trimmedKey, 0, trimmedKey.length);
                return android.util.Base64.encodeToString(trimmedKey, android.util.Base64.DEFAULT);
            } else {
                throw new TSSClientError("Invalid public key bytes");
            }
        }

        if (pubKey.length == 64) {
            return android.util.Base64.encodeToString(pubKey, android.util.Base64.DEFAULT);

        }

        throw new TSSClientError("Invalid public key bytes");
    }

    public static String hexUncompressedPublicKey(byte[] pubKey, boolean return64Bytes) throws TSSClientError {
        if (pubKey.length == 65 && return64Bytes) {
            // Check if the first byte is 0x04 indicating uncompressed format
            if (pubKey[0] == 0x04) {
                byte[] droppedPrefix = new byte[pubKey.length - 1];
                System.arraycopy(pubKey, 1, droppedPrefix, 0, droppedPrefix.length);
                return bytesToHex(droppedPrefix);
            } else {
                throw new TSSClientError("Invalid public key bytes");
            }
        } else if (!return64Bytes) {
            return bytesToHex(pubKey);
        }

        if (pubKey.length == 65 && !return64Bytes) {
            return bytesToHex(pubKey);
        } else if (return64Bytes) { // first byte should be 0x04 prefix
            byte[] prefixedPK = new byte[pubKey.length + 1];
            prefixedPK[0] = 0x04;
            System.arraycopy(pubKey, 0, prefixedPK, 1, pubKey.length);
            return bytesToHex(prefixedPK);
        }

        throw new TSSClientError("Invalid public key bytes");
    }

    public static String base64ToBase64url(String base64) {
        return base64.replace("+", "-")
                .replace("/", "_")
                .replace("=", "");
    }

    public static String hexSignature(BigInteger s, BigInteger r, byte v) throws TSSClientError {
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        if (rBytes.length > 32 || sBytes.length > 32) {
            throw new TSSClientError("Problem with signature components");
        }

        byte[] paddedR = new byte[32];
        byte[] paddedS = new byte[32];

        // Pad with leading zeros if necessary
        int rOffset = 32 - rBytes.length;
        int sOffset = 32 - sBytes.length;

        System.arraycopy(rBytes, 0, paddedR, rOffset, rBytes.length);
        System.arraycopy(sBytes, 0, paddedS, sOffset, sBytes.length);

        byte[] signatureBytes = new byte[65];
        signatureBytes[0] = v;
        System.arraycopy(paddedR, 0, signatureBytes, 1, 32);
        System.arraycopy(paddedS, 0, signatureBytes, 33, 32);

        return bytesToHex(signatureBytes);
    }

    public static byte[] getFinalTssPublicKey(byte[] dkgPubKey, byte[] userSharePubKey, BigInteger userTssIndex) throws Exception {
        BigInteger serverLagrangeCoefficient = TSSHelpers.getLagrangeCoefficients(new BigInteger[]{BigInteger.ONE, userTssIndex}, BigInteger.ONE);
        BigInteger userLagrangeCoefficient = TSSHelpers.getLagrangeCoefficients(new BigInteger[]{BigInteger.ONE, userTssIndex}, userTssIndex);

        ECCurve curve = ECNamedCurveTable.getByName("secp256k1").getCurve();

        ECPoint parsedDkgPubKey = curve.decodePoint(dkgPubKey);
        ECPoint parsedUserSharePubKey = curve.decodePoint(userSharePubKey);

        if (parsedDkgPubKey == null) {
            throw new TorusException("dkgPublicKey is invalid");
        }

        if (parsedUserSharePubKey == null) {
            throw new TorusException("userSharePubKey is invalid");
        }

        byte[] serverLagrangeCoeffData = TSSHelpers.ensureDataLengthIs32Bytes(serverLagrangeCoefficient.toByteArray());
        byte[] userLagrangeCoeffData = TSSHelpers.ensureDataLengthIs32Bytes(userLagrangeCoefficient.toByteArray());

        ECPoint serverTerm = SECP256K1.ecdh(parsedDkgPubKey, serverLagrangeCoeffData);
        ECPoint userTerm = SECP256K1.ecdh(parsedUserSharePubKey, userLagrangeCoeffData);

        byte[] serializedServerTerm = serverTerm.getEncoded(false);
        byte[] serializedUserTerm = userTerm.getEncoded(false);

        byte[][] keys = new byte[][]{serializedServerTerm, serializedUserTerm};
        ECPoint combined = SECP256K1.combineSerializedPublicKeys(keys);

        return combined.getEncoded(false);
    }

    public static byte[] getFinalTssPublicKey1(byte[] dkgPubKey, byte[] userSharePubKey, BigInteger userTssIndex) throws TSSClientError, IOException {
        BigInteger serverLagrangeCoeff = TSSHelpers.getLagrangeCoefficients(new BigInteger[]{BigInteger.ONE, userTssIndex}, BigInteger.ONE);
        BigInteger userLagrangeCoeff = TSSHelpers.getLagrangeCoefficients(new BigInteger[]{BigInteger.ONE, userTssIndex}, userTssIndex);

        ECPoint serverTermUnprocessed = SECP256K1.parsePublicKey(dkgPubKey);
        ECPoint userTermUnprocessed = SECP256K1.parsePublicKey(userSharePubKey);

        if (serverTermUnprocessed == null || userTermUnprocessed == null) {
            throw new TSSClientError("InvalidPublicKey");
        }

        ECPoint serverTerm = serverTermUnprocessed;
        ECPoint userTerm = userTermUnprocessed;

        byte[] serverLagrangeCoeffData = TSSHelpers.ensureDataLengthIs32Bytes(serverLagrangeCoeff.toByteArray());
        byte[] userLagrangeCoeffData = TSSHelpers.ensureDataLengthIs32Bytes(userLagrangeCoeff.toByteArray());

        ECPoint serverTermProcessed = SECP256K1.ecdh(serverTerm, serverLagrangeCoeffData);
        ECPoint userTermProcessed = SECP256K1.ecdh(userTerm, userLagrangeCoeffData);

        if (serverTermProcessed == null || userTermProcessed == null) {
            throw new TSSClientError("Failed to process server term");
        }

        serverTerm = serverTermProcessed;
        userTerm = userTermProcessed;

        byte[] serializedServerTerm = SECP256K1.serializePublicKey(serverTerm, false);
        byte[] serializedUserTerm = SECP256K1.serializePublicKey(userTerm, false);

        if (serializedServerTerm == null || serializedUserTerm == null) {
            throw new TSSClientError("Failed to process client term");
        }

        byte[] combination = SECP256K1.combineSerializedPublicKeys(new byte[][] { serializedServerTerm, serializedUserTerm }, false);

        if (combination == null) {
            throw new TSSClientError("Failed to combine keys");
        }

        return combination;
    }

    private static byte[] ensureDataLengthIs32Bytes(byte[] data) {
        if (data.length == 32) {
            return data;
        } else if (data.length > 32) {
            return Arrays.copyOfRange(data, data.length - 32, data.length);
        } else {
            byte[] newData = new byte[32];
            System.arraycopy(data, 0, newData, 32 - data.length, data.length);
            return newData;
        }
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static BigInteger getLagrangeCoefficients(BigInteger[] allIndexes, BigInteger myIndex) {
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

    public static BigInteger getAdditiveCoefficient(boolean isUser, BigInteger[] participatingServerIndexes, BigInteger userTSSIndex, BigInteger serverIndex) throws TSSClientError {
        if (isUser) {
            return getLagrangeCoefficients(new BigInteger[]{new BigInteger("1"), userTSSIndex}, userTSSIndex);
        }
        if (serverIndex != null) {
            BigInteger serverLagrangeCoeff = getLagrangeCoefficients(participatingServerIndexes, serverIndex);
            BigInteger masterLagrangeCoeff = getLagrangeCoefficients(new BigInteger[]{BigInteger.ONE, userTSSIndex}, BigInteger.ONE);
            BigInteger additiveLagrangeCoeff = serverLagrangeCoeff.multiply(masterLagrangeCoeff).mod(secp256k1N);
            return additiveLagrangeCoeff;
        } else {
            throw new TSSClientError("isUser is false, serverIndex must be supplied");
        }
    }

    public static BigInteger getDenormalizedCoefficient(BigInteger party, List<BigInteger> parties) {
        if (!parties.contains(party)) {
            throw new IllegalArgumentException("party " + party + " not found in parties " + parties);
        }

        BigInteger denormaliseLagrangeCoeff = getLagrangeCoefficients(parties.toArray(new BigInteger[0]), party).modInverse(secp256k1N);
        return denormaliseLagrangeCoeff;
    }

    public static BigInteger getDKLSCoefficient(boolean isUser, List<BigInteger> participatingServerIndexes, BigInteger userTssIndex, BigInteger serverIndex) throws TSSClientError {
        List<BigInteger> sortedServerIndexes = new ArrayList<>(participatingServerIndexes);
        Collections.sort(sortedServerIndexes);

        for (int i = 0; i < sortedServerIndexes.size(); i++) {
            if (!sortedServerIndexes.get(i).equals(participatingServerIndexes.get(i))) {
                throw new TSSClientError("server indexes must be sorted");
            }
        }

        List<BigInteger> parties = new ArrayList<>();
        BigInteger serverPartyIndex = BigInteger.ZERO;

        for (int i = 0; i < participatingServerIndexes.size(); i++) {
            BigInteger currentPartyIndex = BigInteger.valueOf(i + 1);
            parties.add(currentPartyIndex);
            if (participatingServerIndexes.get(i).equals(serverIndex)) {
                serverPartyIndex = currentPartyIndex;
            }
        }

        BigInteger userPartyIndex = BigInteger.valueOf(parties.size() + 1);
        parties.add(userPartyIndex);

        BigInteger additiveCoeff = TSSHelpers.getAdditiveCoefficient(isUser, participatingServerIndexes.toArray(new BigInteger[0]), userTssIndex, serverIndex);

        if (isUser) {
            BigInteger denormaliseCoeff = TSSHelpers.getDenormalizedCoefficient(userPartyIndex, parties);
            return denormaliseCoeff.multiply(additiveCoeff).mod(TSSClient.modulusValueSigned);
        } else {
            BigInteger denormaliseCoeff = TSSHelpers.getDenormalizedCoefficient(serverPartyIndex, parties);
            return denormaliseCoeff.multiply(additiveCoeff).mod(TSSClient.modulusValueSigned);
        }
    }

    public static boolean verifySignature(String msgHash, BigInteger s, BigInteger r, byte v, byte[] pubKey) {
        try {
            String pk = TSSHelpers.recoverPublicKey(msgHash, s, r, v);
            assert pk != null;
            return pk.getBytes(StandardCharsets.UTF_8) == pubKey;
        } catch (Exception e) {
            return false;
        }
    }
    public static String recoverPublicKey(String msgHash, BigInteger s, BigInteger r, byte v) {
        Sign.SignatureData signatureData  = new Sign.SignatureData(v, r.toByteArray(), s.toByteArray());
        int header = 0;
        for (byte b : signatureData.getV()) {
            header = (header << 8) + (b & 0xFF);
        }
        if (header < 27 || header > 34) {
            return null;
        }
        int recId = header - 27;
        BigInteger key = Sign.recoverFromSignature(
                recId,
                new ECDSASignature(
                        new BigInteger(1, signatureData.getR()), new BigInteger(1, signatureData.getS())),
                Numeric.hexStringToByteArray(msgHash));
        if (key == null) {
            return null;
        }
        return ("0x" + Keys.getAddress(key)).trim();
    }

    public static String assembleFullSession(String verifier, String verifierId, String tssTag, String tssNonce, String sessionNonce) {
        String fullSession = verifier + DELIMITERS.Delimiter1 +
                verifierId + DELIMITERS.Delimiter2 +
                tssTag + DELIMITERS.Delimiter3 +
                tssNonce + DELIMITERS.Delimiter4 +
                sessionNonce;

        return fullSession;
    }

    public static Map<String, String> getServerCoefficients(BigInteger[] participatingServerDKGIndexes, BigInteger userTssIndex) throws TSSClientError {
        Map<String, String> serverCoeffs = new HashMap<>();
        for (int i = 0; i < participatingServerDKGIndexes.length; i++) {
            BigInteger participatingServerIndex = participatingServerDKGIndexes[i];
            BigInteger coefficient = TSSHelpers.getDKLSCoefficient(
                    false, List.of(participatingServerDKGIndexes), userTssIndex, participatingServerIndex
            );

            // Values should never contain leading zeros
            String key = TSSHelpers.removeLeadingZeros(participatingServerIndex.toString(16));
            String value = TSSHelpers.removeLeadingZeros(coefficient.toString(16));
            serverCoeffs.put(key, value);
        }

        return serverCoeffs;
    }

    public static String addLeadingZerosForLength64(String str) {
        if (str.length() < 64) {
            String toAdd = "0".repeat(64 - str.length());
            return toAdd + str;
        } else {
            return str;
        }
    }

    public static String removeLeadingZeros(String str) {
        int found = -1;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) != '0') {
                found = i;
                break;
            }
        }

        if (found != -1) {
            return str.substring(found);
        } else {
            if (str.isEmpty()) {
                return str;
            } else {
                return "0";
            }
        }
    }
}
