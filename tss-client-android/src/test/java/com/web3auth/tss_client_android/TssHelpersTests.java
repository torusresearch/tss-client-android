package com.web3auth.tss_client_android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.web3j.utils.Numeric.hexStringToByteArray;

import com.web3auth.tss_client_android.client.TSSClientError;
import com.web3auth.tss_client_android.client.TSSHelpers;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TssHelpersTests {
    @Test
    public void testGetLagrange() {
        BigInteger[] parties = { new BigInteger("50"), new BigInteger("100") };
        BigInteger party = new BigInteger("10");
        BigInteger result = TSSHelpers.getLagrangeCoefficients(parties, party);
        String expected = TSSHelpers.addLeadingZerosForLength64("f1c71c71c71c71c71c71c71c71c71c7093de09848919ecaa352a3cda52dde84d");
        assertEquals(expected, result.toString(16));
    }

    @Test
    public void testGetAdditiveCoefficient() throws TSSClientError {
        BigInteger[] participatingServerIndexes = { new BigInteger("100"), new BigInteger("200"), new BigInteger("300") };
        BigInteger userTSSIndex = new BigInteger("10");
        BigInteger result = TSSHelpers.getAdditiveCoefficient(true, participatingServerIndexes, userTSSIndex, null);
        String expected = TSSHelpers.addLeadingZerosForLength64("71c71c71c71c71c71c71c71c71c71c7136869b1131759c8c55410d93eac2c7ab");
        assertEquals(expected, result.toString(16));

        BigInteger[] participatingServerIndexes1 = { new BigInteger("1"), new BigInteger("4"), new BigInteger("5") };
        BigInteger userTSSIndex1 = new BigInteger("3");
        BigInteger serverIndex = new BigInteger("1");
        BigInteger coeff = TSSHelpers.getAdditiveCoefficient(true, participatingServerIndexes1, userTSSIndex1, serverIndex);
        BigInteger compare = new BigInteger("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", 16);
        assertEquals(coeff, compare);
    }

    @Test
    public void testGetDenormalizedCoefficient() {
        BigInteger party = new BigInteger("100");
        BigInteger[] parties = { new BigInteger("100"), new BigInteger("200") };
        BigInteger result = TSSHelpers.getDenormalizedCoefficient(party, List.of(parties));
        String expected = TSSHelpers.addLeadingZerosForLength64("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
        assertEquals(expected, result.toString(16));
    }

    @Test
    public void testGetDKLSCoefficient() throws TSSClientError {
        BigInteger[] participatingServerIndexes1 = { new BigInteger("1"), new BigInteger("4"), new BigInteger("5") };
        BigInteger userTssIndex1 = new BigInteger("3");
        BigInteger dklsCoeff = TSSHelpers.getDKLSCoefficient(true, List.of(participatingServerIndexes1), userTssIndex1, null);
        BigInteger compare = new BigInteger("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1", 16);
        assertTrue(dklsCoeff.equals(compare));

        BigInteger coeff2 = TSSHelpers.getDKLSCoefficient(false, List.of(new BigInteger[]{new BigInteger("1"), new BigInteger("2"), new BigInteger("5")}), new BigInteger("3"), new BigInteger("2"));
        BigInteger comp = new BigInteger("955555555555555555555555555555549790ab8690ea5d782fe561d2241fa611", 16);
        assertTrue(coeff2.equals(comp));

        BigInteger[] participatingServerIndexes = { new BigInteger("100"), new BigInteger("200") };
        BigInteger userTssIndex = new BigInteger("100");
        BigInteger result = TSSHelpers.getDKLSCoefficient(true, List.of(participatingServerIndexes), userTssIndex, null);
        String expected = TSSHelpers.addLeadingZerosForLength64("a57eb50295fad40a57eb50295fad40a4ac66b301bc4dfafaaa8d2b05b28fae1");
        assertEquals(expected, result.toString(16));
    }

    @Test
    public void testFinalGetTSSPubkey() throws Exception {
        byte[] dkgpub = new byte[1 + 32 + 32];
        dkgpub[0] = 0x04;
        byte[] xCoord1 = hexStringToByteArray("18db3574e4217154769ad9cd88900e7f1c198aa60a1379f3869ba8a7699e6b53");
        System.arraycopy(xCoord1, 0, dkgpub, 1, xCoord1.length);
        byte[] yCoord1 = hexStringToByteArray("d4f7d578667c38003f881f262e21655a38241401d9fc029c9a6fcbca8ac97713");
        System.arraycopy(yCoord1, 0, dkgpub, xCoord1.length + 1, yCoord1.length);

        byte[] userpub = new byte[1 + 32 + 32];
        userpub[0] = 0x04;
        byte[] xCoord2 = hexStringToByteArray("b4259bffab844a5255ba0c8f278b7fd857c094460b9051c95f04b29f9792368c");
        System.arraycopy(xCoord2, 0, userpub, 1, xCoord2.length);
        byte[] yCoord2 = hexStringToByteArray("790eb133df835aa22fd087d5e33b26f2d2e046b6670ac7603500bc1227216247");
        System.arraycopy(yCoord2, 0, userpub, xCoord2.length + 1, yCoord2.length);


        BigInteger userTssIndex = new BigInteger("2");

        byte[] tssPub = TSSHelpers.getFinalTssPublicKey1(dkgpub, userpub, userTssIndex);
        String expected = "04dd1619c7e99eb665e37c74828762e6a677511d4c52656ddc6499a57d486bddb8c0dc63b229ec9a31f4216138c3fbb67ac2630831135aecbaf0aafa095e439c61";
        assertEquals(expected, Hex.toHexString(tssPub));
    }

    @Test
    public void testRemoveLeadingZeros() {
        String string = "000010";
        String result = TSSHelpers.removeLeadingZeros(string);
        assertEquals("10", result);

        String str = "10";
        String res = TSSHelpers.removeLeadingZeros(str);
        assertEquals(str, res);

        str = "0100056";
        res = TSSHelpers.removeLeadingZeros(str);
        assertEquals("100056", res);

        str = "";
        res = TSSHelpers.removeLeadingZeros(str);
        assertEquals("", res);

        str = "000000";
        res = TSSHelpers.removeLeadingZeros(str);
        assertEquals("0", res);
    }

    @Test
    public void testGetServerCoefficients() throws TSSClientError {
        Map<String, String> coefficients_index3 = new HashMap<>();
        coefficients_index3.put("1", "1");
        coefficients_index3.put("2", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
        coefficients_index3.put("4", "dffffffffffffffffffffffffffffffee3590149d95f8c3447d812bb362f7919");

        Map<String, String> coeffs_index3 = TSSHelpers.getServerCoefficients(
                new BigInteger[] { new BigInteger("1"), new BigInteger("2"), new BigInteger("4") },
                new BigInteger("3")
        );

        assertEquals(coefficients_index3, coeffs_index3);

        Map<String, String> coefficients_index2 = new HashMap<>();
        coefficients_index2.put("1", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a2");
        coefficients_index2.put("2", "1");
        coefficients_index2.put("3", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");

        Map<String, String> coeffs_index2 = TSSHelpers.getServerCoefficients(
                new BigInteger[] { new BigInteger("1"), new BigInteger("2"), new BigInteger("3") },
                new BigInteger("2")
        );

        assertEquals(coefficients_index2, coeffs_index2);
    }
}

