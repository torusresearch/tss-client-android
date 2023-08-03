package com.web3auth.tss_client_android.client;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;

public class SECP256K1 {

    private static final int PRIVATE_KEY_LENGTH = 32;
    private static SecureRandom random = new SecureRandom();

    public static boolean verifyPrivateKey(byte[] privateKey) {
        if (privateKey.length != PRIVATE_KEY_LENGTH) {
            return false;
        }
        int result = secp256k1_ec_seckey_verify(context, privateKey);
        return result == 1;
    }

    public static byte[] generatePrivateKey() {
        for (int i = 0; i < 1024; i++) {
            byte[] keyData = new byte[32];
            random.nextBytes(keyData);
            if (verifyPrivateKey(keyData)) {
                return keyData;
            }
        }
        return null;
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

    public static ECPoint combineSerializedPublicKeys(byte[][] keys) {
        ECCurve curve = ECNamedCurveTable.getParameterSpec("secp256k1").getCurve();
        ECPoint result = curve.getInfinity();
        for (byte[] key : keys) {
            ECPoint point = curve.decodePoint(key);
            result = result.add(point);
        }
        return result;
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
