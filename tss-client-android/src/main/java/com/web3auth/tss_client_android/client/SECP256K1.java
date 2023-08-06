package com.web3auth.tss_client_android.client;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class SECP256K1 {

    private static final int PRIVATE_KEY_LENGTH = 32;
    private static SecureRandom random = new SecureRandom();

    {
        setupBouncyCastle();
    }

    private void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            // Web3j will set up the provider lazily when it's first used.
            return;
        }
        if (provider.getClass().equals(BouncyCastleProvider.class)) {
            // BC with same package name, shouldn't happen in real life.
            return;
        }
        // Android registers its own BC provider. As it might be outdated and might not include
        // all needed ciphers, we substitute it with a known BC bundled in the app.
        // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
        // of that it's possible to have another BC implementation loaded in VM.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public static boolean verifyPrivateKey(byte[] privateKeyBytes) {
        if (privateKeyBytes.length != PRIVATE_KEY_LENGTH) {
            return false;
        }
        try {
            X9ECParameters curveParams = CustomNamedCurves.getByName("secp256k1");
            ECDomainParameters domainParams = new ECDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH());
            ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), domainParams);
            ECPoint publicKeyPoint = domainParams.getG().multiply(privateKeyParams.getD());
            byte[] publicKeyBytes = publicKeyPoint.getEncoded(false);
            ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(publicKeyPoint, domainParams);
            boolean isValid = Arrays.equals(publicKeyParams.getQ().getEncoded(false), publicKeyBytes);
            return isValid;
        } catch (Exception e) {
            return false;
        }
    }

    public static BigInteger generatePrivateKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECKeyPair tmpKey = Keys.createEcKeyPair();
        return tmpKey.getPrivateKey();
    }

    public static BigInteger privateToPublic(String privateKey) {
        ECKeyPair ecKeyPair = ECKeyPair.create(new BigInteger(privateKey, 16));
        return ecKeyPair.getPublicKey();
    }

    public static UnmarshaledSignature unmarshalSignature(byte[] signatureData) {
        if (signatureData.length != 65) {
            return null;
        }
        byte v = signatureData[64];
        byte[] r = Arrays.copyOfRange(signatureData, 0, 32);
        byte[] s = Arrays.copyOfRange(signatureData, 32, 64);
        return new UnmarshaledSignature(v, r, s);
    }

    public static ECPoint parsePublicKey(byte[] serializedKey) {
        ECCurve curve = ECNamedCurveTable.getParameterSpec("secp256k1").getCurve();
        int keyLen = serializedKey.length;
        if (keyLen != 33 && keyLen != 65) {
            return null;
        }

        byte[] keyBytes = Arrays.copyOf(serializedKey, keyLen);
        if (keyLen == 65 && keyBytes[0] == 0x04) {
            keyBytes = Arrays.copyOfRange(keyBytes, 1, keyLen);
        }

        return curve.decodePoint(keyBytes);
    }

    public static ECPoint ecdh(ECPoint pubKey, byte[] privateKey) {
        if (privateKey.length != 32) {
            return null;
        }

        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        BigInteger a = BigInteger.ZERO;
        BigInteger b = new BigInteger("7");
        ECCurve curve = new ECCurve.Fp(p, a, b);
        ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, pubKey, a, b);

        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(new BigInteger(1, privateKey), ecDomainParameters);
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(pubKey, ecDomainParameters);

        FixedPointCombMultiplier multiplier = new FixedPointCombMultiplier();
        ECPoint result = multiplier.multiply(pubKey, privateKeyParams.getD());

        return result;
    }

    /*private static ECPointArithmetic ecdh(String privateKeyHex, String ephemPublicKeyHex) {
        String affineX = ephemPublicKeyHex.substring(2, 66);
        String affineY = ephemPublicKeyHex.substring(66);

        ECPointArithmetic ecPoint = new ECPointArithmetic(new EllipticCurve(
                new ECFieldFp(new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")),
                new BigInteger("0"),
                new BigInteger("7")), new BigInteger(affineX, 16), new BigInteger(affineY, 16), null);
        return ecPoint.multiply(new BigInteger(privateKeyHex, 16));
    }*/

    public static byte[] serializePublicKey(ECPoint publicKey, boolean compressed) {
        ECCurve curve = publicKey.getCurve();
        int keyLength = compressed ? 33 : 65;

        byte[] serializedPubkey = new byte[keyLength];
        byte[] pointData = publicKey.getEncoded(compressed);

        // Fill with leading zeros if needed
        int offset = keyLength - pointData.length;
        if (offset > 0) {
            System.arraycopy(pointData, 0, serializedPubkey, offset, pointData.length);
        } else {
            serializedPubkey = pointData;
        }

        return serializedPubkey;
    }

    public static ECPoint combineSerializedPublicKeys(byte[][] keys) {
        ECCurve curve = ECNamedCurveTable.getParameterSpec("secp256k1").getCurve();
        ECPoint result = curve.getInfinity();
        for (byte[] key : keys) {
            ECPoint point = curve.decodePoint(key);
            result = result.add(point);
        }
        return result;
    }

    public static byte[] combineSerializedPublicKeys(byte[][] keys, boolean outputCompressed) {
        int numToCombine = keys.length;
        if (numToCombine < 1) {
            return null;
        }

        ECPoint[] points = new ECPoint[numToCombine];
        for (int i = 0; i < numToCombine; i++) {
            byte[] keyData = keys[i];
            ECPoint publicKey = SECP256K1.parsePublicKey(keyData);
            if (publicKey == null) {
                return null;
            }
            points[i] = publicKey;
        }

        byte[][] byteArray = new byte[numToCombine][];
        for (int i = 0; i < numToCombine; i++) {
            byte[] data = SECP256K1.serializePublicKey(points[i], false);
            byteArray[i] = data;
        }

        ECPoint combinedPoint = SECP256K1.combineSerializedPublicKeys(byteArray);
        if (combinedPoint == null) {
            return null;
        }

        return combinedPoint.getEncoded(outputCompressed);
    }


    public static byte[] privateKeyToPublicKey(byte[] privateKey) {
        if (privateKey.length != 32) {
            return null;
        }

        X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        BigInteger privKeyInt = new BigInteger(1, privateKey);
        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(privKeyInt, domainParams);
        ECPoint publicKeyPoint = params.getG().multiply(privKeyInt);

        // Get the public key as a byte array.
        byte[] publicKeyBytes = publicKeyPoint.getEncoded(true);
        System.out.println("Public Key (hex): " + Hex.toHexString(publicKeyBytes));
        return publicKeyBytes;
    }

    public static byte[] marshalSignature(byte v, byte[] r, byte[] s) {
        if (r.length != 32 || s.length != 32) {
            return null;
        }
        byte[] completeSignature = new byte[65];
        System.arraycopy(r, 0, completeSignature, 0, 32);
        System.arraycopy(s, 0, completeSignature, 32, 32);
        completeSignature[64] = v;
        return completeSignature;
    }

    public static byte[] marshalSignature(byte[] v, byte[] r, byte[] s) {
        if (r.length != 32 || s.length != 32) {
            return null;
        }
        byte[] completeSignature = new byte[65];
        System.arraycopy(r, 0, completeSignature, 0, 32);
        System.arraycopy(s, 0, completeSignature, 32, 32);
        System.arraycopy(v, 0, completeSignature, 64, 1);
        return completeSignature;
    }

    public static byte[] randomBytes(int length) {
        byte[] data = new byte[length];
        for (int i = 0; i < 1024; i++) {
            random.nextBytes(data);
            if (verifyPrivateKey(data)) {
                return data;
            }
        }
        return null;
    }

    public static byte[] toByteArray(short value) {
        ByteBuffer buffer = ByteBuffer.allocate(2);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort(value);
        return buffer.array();
    }

    public static short fromByteArrayToShort(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        return buffer.getShort();
    }

    public static byte[] toByteArray(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(value);
        return buffer.array();
    }

    public static int fromByteArrayToInt(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        return buffer.getInt();
    }

    public static boolean constantTimeComparison(byte[] lhs, byte[] rhs) {
        if (lhs.length != rhs.length) {
            return false;
        }
        byte difference = 0x00;
        for (int i = 0; i < lhs.length; i++) {
            difference |= lhs[i] ^ rhs[i];
        }
        return difference == 0x00;
    }

    public static class UnmarshaledSignature {
        public byte v = 0;
        public byte[] r = new byte[32];
        public byte[] s = new byte[32];

        public UnmarshaledSignature(byte v, byte[] r, byte[] s) {
            this.v = v;
            this.r = r;
            this.s = s;
        }
    }
}
