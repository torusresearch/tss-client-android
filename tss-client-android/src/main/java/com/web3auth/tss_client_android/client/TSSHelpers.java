package com.web3auth.tss_client_android.client;

import static com.web3auth.tss_client_android.client.util.ByteUtils.bytesToHex;

import android.util.Base64;

import com.web3auth.tss_client_android.client.util.Secp256k1;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.web3j.crypto.Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TSSHelpers {
    // singleton class
    private TSSHelpers() {
    }

    /**
     * Hashes a message using Hash.sha3
     * @param message The message to be hashed.
     * @return String
     */
    public static String hashMessage(String message) {
        byte[] hashedData = Hash.sha3(message.getBytes(StandardCharsets.UTF_8));
        return android.util.Base64.encodeToString(hashedData, android.util.Base64.NO_WRAP);
    }

    /**
     * Converts a share to base64
     * @param share The share to be converted.
     * @return String
     * @throws TSSClientError if share is negative
     */
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
        return android.util.Base64.encodeToString(last32Bytes, Base64.NO_WRAP);
    }

    /**
     * Verifies the message hash and signature components using the pubKey
     * @param msgHash The hash of the message.
     * @param s S component of signature
     * @param r R component of signature
     * @param v Recovery parameter of signature
     * @param pubKey The public key to be checked against, 65 byte representation
     * @return Boolean
     */
    public static boolean verifySignature(String msgHash, BigInteger s, BigInteger r, byte v, byte[] pubKey) {
        byte[] pk = TSSHelpers.recoverPublicKey(msgHash, s, r, v);
        return java.util.Arrays.equals(pk, pubKey);
    }

    /**
     * Recovers the public key from the message hash and the signature components
     * @param msgHash The hash of the message.
     * @param s S component of signature
     * @param r R component of signature
     * @param v Recovery parameter of signature
     * @return byte array
     */
    public static byte[] recoverPublicKey(String msgHash, BigInteger s, BigInteger r, byte v) {
        Secp256k1.ECDSASignature signature = Secp256k1.ECDSASignature.fromComponents(r.toByteArray(), s.toByteArray(), v);
        byte[] msgData = android.util.Base64.decode(msgHash, android.util.Base64.NO_WRAP);
        return Secp256k1.RecoverPubBytesFromSignature(msgData, signature.toByteArray());
    }

    /**
     * Converts a public key to base64.
     * @param pubKey The public key, either 65 or 64 byte representation
     * @return String
     * @throws TSSClientError if public key bytes are invalid
     */
    public static String base64PublicKey(byte[] pubKey) throws TSSClientError {
        if (pubKey.length == 65) {
            byte[] trimmedKey = new byte[pubKey.length - 1];
            System.arraycopy(pubKey, 1, trimmedKey, 0, trimmedKey.length);
            return android.util.Base64.encodeToString(trimmedKey, Base64.NO_WRAP);
        }

        if (pubKey.length == 64) {
            return android.util.Base64.encodeToString(pubKey, Base64.NO_WRAP);

        }

        throw new TSSClientError("Invalid public key bytes");
    }

    /**
     * Converts a public key to hex
     * @param pubKey The public key, either 65 or 64 byte representation
     * @param return64Bytes whether to use the 65 or 64 byte representation when converting to hex
     * @return String
     * @throws TSSClientError if public key bytes are invalid
     */
    public static String hexUncompressedPublicKey(byte[] pubKey, boolean return64Bytes) throws TSSClientError {
        if (pubKey.length == 65) {
            if (return64Bytes) {
                // Check if the first byte is 0x04 indicating uncompressed format
                if (pubKey[0] == 0x04) {
                    byte[] droppedPrefix = new byte[pubKey.length - 1];
                    System.arraycopy(pubKey, 1, droppedPrefix, 0, droppedPrefix.length);
                    return bytesToHex(droppedPrefix);
                } else {
                    throw new TSSClientError("Invalid public key bytes");
                }
            } else {
                return bytesToHex(pubKey);
            }
        }

        if (pubKey.length == 64) {
            if (return64Bytes) {
                return bytesToHex(pubKey);
            } else { // first byte should be 0x04 prefix
                byte[] prefixedPK = new byte[pubKey.length + 1];
                prefixedPK[0] = 0x04;
                System.arraycopy(pubKey, 0, prefixedPK, 1, pubKey.length);
                return bytesToHex(prefixedPK);
            }
        }

        throw new TSSClientError("Invalid public key bytes");
    }

    /**
     * Converts a base64 string to a url safe base64 string
     * @param base64 The string to convert
     * @return String
     */
    public static String base64ToBase64url(String base64) {
        return base64.replace("+", "-")
                .replace("/", "_")
                .replace("=", "");
    }

    /**
     * Converts signature components to the hex representation
     * @param s S component of signature
     * @param r R component of signature
     * @param v Recovery parameter of signature
     * @return String
     */
    public static String hexSignature(BigInteger s, BigInteger r, byte v) {
        Secp256k1.ECDSASignature signature = Secp256k1.ECDSASignature.fromComponents(r.toByteArray(), s.toByteArray(), v);
        return signature.toHex();
    }

    /**
     * Calculates server coefficients based on the distributed key generation indexes and the user tss index
     * @param participatingServerDKGIndexes The array of indexes for the participating servers.
     * @param userTssIndex The current tss index for the user
     * @return Map of String: String
     * @throws TSSClientError if participatingServerDKGIndexes indexes are not sorted
     */
    public static Map<String, String> getServerCoefficients(BigInteger[] participatingServerDKGIndexes, BigInteger userTssIndex) throws TSSClientError {
        LinkedHashMap<String, String> serverCoeffs = new LinkedHashMap<>();
        for (BigInteger participatingServerIndex : participatingServerDKGIndexes) {
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

    /**
     * Calculates client(user) coefficients based on the distributed key generation indexes and the user tss index
     * @param participatingServerDKGIndexes The array of indexes for the participating servers.
     * @param userTssIndex The current tss index for the user
     * @return String
     * @throws TSSClientError if participatingServerDKGIndexes indexes are not sorted
     */
    public static String getClientCoefficients(BigInteger[] participatingServerDKGIndexes, BigInteger userTssIndex) throws TSSClientError {
        BigInteger coeff;
        try {
            coeff = getDKLSCoefficient(true, List.of(participatingServerDKGIndexes), userTssIndex, null);
            return serializeToHexString(coeff);
        } catch (Exception e) {
            throw new TSSClientError(e.getMessage());
        }
    }

    /**
     * Calculates client(user) denormalise Share based on the distributed key generation indexes and the user tss index
     * @param participatingServerDKGIndexes The array of indexes for the participating servers.
     * @param userTssIndex The current tss index for the user
     * @param userTssShare The current tss share for the user
     * @return bigInteger
     * @throws TSSClientError if participatingServerDKGIndexes indexes are not sorted
     */
    public static BigInteger denormalizeShare(BigInteger[] participatingServerDKGIndexes, BigInteger userTssIndex, BigInteger userTssShare) throws TSSClientError {
        try {
            BigInteger coeff = getDKLSCoefficient(true, List.of(participatingServerDKGIndexes), userTssIndex, null);
            return coeff.multiply(userTssShare).mod(Secp256k1.CURVE.getN());
        } catch (Exception e) {
            throw new TSSClientError(e.getMessage());
        }
    }

    /**
     * Calculates the public key that will be used for TSS signing.
     * @param dkgPubKey The public key resulting from distributed key generation.
     * @param userSharePubKey The public key for the current TSS share
     * @param userTssIndex The current tss index for the user
     * @return byte array
     * @throws TSSClientError if dkgPublicKey or userSharePubKey is invalid
     */
    public static byte[] getFinalTssPublicKey(byte[] dkgPubKey, byte[] userSharePubKey, BigInteger userTssIndex) throws TSSClientError {
        BigInteger serverLagrangeCoefficient = TSSHelpers.getLagrangeCoefficient(new BigInteger[]{new BigInteger("1"), userTssIndex}, new BigInteger("1"));
        BigInteger userLagrangeCoefficient = TSSHelpers.getLagrangeCoefficient(new BigInteger[]{new BigInteger("1"), userTssIndex}, userTssIndex);

        ECCurve curve = Secp256k1.CURVE.getCurve();
        ECPoint parsedDkgPubKey = curve.decodePoint(dkgPubKey);
        ECPoint parsedUserSharePubKey = curve.decodePoint(userSharePubKey);

        if (parsedDkgPubKey == null) {
            throw new TSSClientError("dkgPublicKey is invalid");
        }

        if (parsedUserSharePubKey == null) {
            throw new TSSClientError("userSharePubKey is invalid");
        }

        byte[] serverLagrangeCoeffData = TSSHelpers.ensureDataLengthIs32Bytes(serverLagrangeCoefficient.toByteArray());
        byte[] userLagrangeCoeffData = TSSHelpers.ensureDataLengthIs32Bytes(userLagrangeCoefficient.toByteArray());

        ECPoint serverTerm = Secp256k1.ecdh(parsedDkgPubKey, serverLagrangeCoeffData);
        ECPoint userTerm = Secp256k1.ecdh(parsedUserSharePubKey, userLagrangeCoeffData);

        ECPoint[] keys = new ECPoint[]{serverTerm, userTerm};
        ECPoint combined = Secp256k1.combinePublicKeys(keys);

        return combined.getEncoded(false);
    }

    public static BigInteger getAdditiveCoefficient(boolean isUser, BigInteger[] participatingServerIndexes, BigInteger userTSSIndex, BigInteger serverIndex) throws TSSClientError {
        if (isUser) {
            return getLagrangeCoefficient(new BigInteger[]{new BigInteger("1"), userTSSIndex}, userTSSIndex);
        }
        if (serverIndex != null) {
            BigInteger serverLagrangeCoeff = getLagrangeCoefficient(participatingServerIndexes, serverIndex);
            BigInteger masterLagrangeCoeff = getLagrangeCoefficient(new BigInteger[]{BigInteger.ONE, userTSSIndex}, BigInteger.ONE);
            return serverLagrangeCoeff.multiply(masterLagrangeCoeff).mod(Secp256k1.CURVE.getN());
        } else {
            throw new TSSClientError("isUser is false, serverIndex must be supplied");
        }
    }

    public static BigInteger getDenormalizedCoefficient(BigInteger party, List<BigInteger> parties) {
        if (!parties.contains(party)) {
            throw new IllegalArgumentException("party " + party + " not found in parties " + parties);
        }

        return getLagrangeCoefficient(parties.toArray(new BigInteger[0]), party).modInverse(Secp256k1.CURVE.getN());
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

        BigInteger denormaliseCoeff;
        if (isUser) {
            denormaliseCoeff = TSSHelpers.getDenormalizedCoefficient(userPartyIndex, parties);
        } else {
            denormaliseCoeff = TSSHelpers.getDenormalizedCoefficient(serverPartyIndex, parties);
        }
        return denormaliseCoeff.multiply(additiveCoeff).mod(Secp256k1.CURVE.getN());
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

    /**
     * Converts array of bytes into hexadecimal string
     * @param bytes The bytes array to convert
     * @return String
     */
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static BigInteger getLagrangeCoefficient(BigInteger[] allIndexes, BigInteger myIndex) {
        BigInteger target = new BigInteger("0");
        return getLagrangeCoefficient(allIndexes, myIndex, target);
    }

    public static BigInteger getLagrangeCoefficient(BigInteger[] allIndexes, BigInteger myIndex, BigInteger target) {
        BigInteger upper = new BigInteger("1");
        BigInteger lower = new BigInteger("1");
        for (BigInteger index : allIndexes) {
            if (myIndex.compareTo(index) != 0) {
                BigInteger tempUpper = target.subtract(index).mod(Secp256k1.CURVE.getN());
                upper = upper.multiply(tempUpper).mod(Secp256k1.CURVE.getN());

                BigInteger tempLower = myIndex.subtract(index).mod(Secp256k1.CURVE.getN());
                lower = lower.multiply(tempLower).mod(Secp256k1.CURVE.getN());
            }
        }
        BigInteger invLower = lower.modInverse(Secp256k1.CURVE.getN());
        return upper.multiply(invLower).mod(Secp256k1.CURVE.getN());
    }

    /**
     * Assembles the full session string from components for signing.
     * @param verifier The name of the verifier.
     * @param verifierId  The current verifier id.
     * @param tssTag The current tss tag.
     * @param tssNonce The current tss nonce.
     * @param sessionNonce The current session nonce.
     * @return String
     */
    public static String assembleFullSession(String verifier, String verifierId, String tssTag, String tssNonce, String sessionNonce) {
        return verifier + Delimiters.Delimiter1 +
                verifierId + Delimiters.Delimiter2 +
                tssTag + Delimiters.Delimiter3 +
                tssNonce + Delimiters.Delimiter4 +
                sessionNonce;
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

    /**
     * Serializes the BigInteger values and then converts it to hexadecimal string.
     * @param value The BigInteger value to convert
     * @return String
     */
    public static String serializeToHexString(BigInteger value) {
        byte[] bytes = value.toByteArray();
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }

    /**
     * Generates endpoints for client based on supplied inputs.
     * @param parties The number of parties.
     * @param clientIndex The index of the client in the number of parties.
     * @return EndpointsData
     */
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

    /**
     * Returns a char sequence with content of this char sequence padded at the beginning to the specified length with the specified character or space.
     * @param inputString The string to be pad from left
     * @param padChar The character to pad string with.
     * @param length The desired string length.
     * @return String
     */
    public static String padLeft(String inputString, Character padChar, int length) {
        if (inputString.length() >= length) return inputString;
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append(padChar);
        }
        sb.append(inputString);
        return sb.toString();
    }
}
