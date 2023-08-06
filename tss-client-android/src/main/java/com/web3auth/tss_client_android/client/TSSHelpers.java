package com.web3auth.tss_client_android.client;

import com.web3auth.tss_client_android.DELIMITERS;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

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
        String base64Encoded;
        base64Encoded = Base64.getEncoder().encodeToString(last32Bytes);
        return base64Encoded;
    }

    public static String base64PublicKey(byte[] pubKey) throws TSSClientError {
        if (pubKey.length == 65) {
            // Check if the first byte is 0x04 indicating uncompressed format
            if (pubKey[0] == 0x04) {
                byte[] droppedPrefix = new byte[pubKey.length - 1];
                System.arraycopy(pubKey, 1, droppedPrefix, 0, droppedPrefix.length);
                return Base64.getEncoder().encodeToString(droppedPrefix);
            } else {
                throw new TSSClientError("Invalid public key bytes");
            }
        } else if (pubKey.length == 64) {
            return Base64.getEncoder().encodeToString(pubKey);
        } else {
            throw new TSSClientError("Invalid public key bytes");
        }
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

        BigInteger serverPrivateKey = serverLagrangeCoefficient.mod(secp256k1N);
        BigInteger userPrivateKey = userLagrangeCoefficient.mod(secp256k1N);

        ECPoint serverTerm = SECP256K1.ecdh(parsedDkgPubKey, serverPrivateKey.toByteArray());
        ECPoint userTerm = SECP256K1.ecdh(parsedUserSharePubKey, userPrivateKey.toByteArray());

        byte[] serializedServerTerm = serverTerm.getEncoded(false);
        byte[] serializedUserTerm = userTerm.getEncoded(false);

        byte[][] keys = new byte[][]{serializedServerTerm, serializedUserTerm};
        ECPoint combined = SECP256K1.combineSerializedPublicKeys(keys);

        return combined.getEncoded(false);
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

    public static BigInteger getAdditiveCoefficient(boolean isUser, BigInteger[] participatingServerIndexes, BigInteger userTSSIndex, BigInteger serverIndex) {
        if (isUser) {
            return getLagrangeCoefficients(new BigInteger[]{new BigInteger("1"), userTSSIndex}, userTSSIndex);
        }
        BigInteger serverLagrangeCoeff = getLagrangeCoefficients(participatingServerIndexes, serverIndex);
        BigInteger masterLagrangeCoeff = getLagrangeCoefficients(new BigInteger[]{new BigInteger("1"), userTSSIndex}, new BigInteger("1"));
        BigInteger additiveLagrangeCoeff = serverLagrangeCoeff.multiply(masterLagrangeCoeff).mod(secp256k1N);
        System.out.println("Additive Coeff: " + additiveLagrangeCoeff);
        return additiveLagrangeCoeff;
    }

    public static BigInteger getDenormalizedCoefficient(BigInteger party, List<BigInteger> parties) {
        if (!parties.contains(party)) {
            throw new IllegalArgumentException("party " + party + " not found in parties " + parties);
        }

        BigInteger denormaliseLagrangeCoeff = getLagrangeCoefficients(parties.toArray(new BigInteger[0]), party).modInverse(secp256k1N);
        return denormaliseLagrangeCoeff;
    }

    public static BigInteger getDKLSCoefficient(boolean isUser, List<BigInteger> participatingServerIndexes,
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
            BigInteger additiveCoeff = getAdditiveCoefficient(isUser, participatingServerIndexes.toArray(new BigInteger[0]), userTSSIndex, serverIndex);
            BigInteger denormaliseCoeff = getDenormalizedCoefficient(userPartyIndex, parties);
            return denormaliseCoeff.multiply(additiveCoeff).mod(secp256k1N);
        }
        BigInteger additiveCoeff = getAdditiveCoefficient(isUser, participatingServerIndexes.toArray(new BigInteger[0]), userTSSIndex, serverIndex);
        BigInteger denormaliseCoeff = getDenormalizedCoefficient(BigInteger.valueOf(serverPartyIndex), parties);
        coeff = denormaliseCoeff.multiply(additiveCoeff).mod(secp256k1N);
        return coeff;
    }

    public static String recoverPublicKey(String msgHash, BigInteger s, BigInteger r, byte v) throws Exception {
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
}
