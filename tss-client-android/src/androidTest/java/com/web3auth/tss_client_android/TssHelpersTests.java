package com.web3auth.tss_client_android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.web3auth.tss_client_android.client.TSSClientError;
import com.web3auth.tss_client_android.client.TSSHelpers;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TssHelpersTests {
    @Test
    public void testGetLagrange() {
        BigInteger[] parties = {new BigInteger("50"), new BigInteger("100")};
        BigInteger party = new BigInteger("10");
        BigInteger result = TSSHelpers.getLagrangeCoefficients(parties, party);
        String expected = TSSHelpers.addLeadingZerosForLength64("f1c71c71c71c71c71c71c71c71c71c7093de09848919ecaa352a3cda52dde84d");
        assertEquals(expected, result.toString(16));
    }

    @Test
    public void testGetAdditiveCoefficient() throws TSSClientError {
        BigInteger[] participatingServerIndexes = {new BigInteger("100"), new BigInteger("200"), new BigInteger("300")};
        BigInteger userTSSIndex = new BigInteger("10");
        BigInteger result = TSSHelpers.getAdditiveCoefficient(true, participatingServerIndexes, userTSSIndex, null);
        String expected = TSSHelpers.addLeadingZerosForLength64("71c71c71c71c71c71c71c71c71c71c7136869b1131759c8c55410d93eac2c7ab");
        assertEquals(expected, result.toString(16));

        BigInteger[] participatingServerIndexes1 = {new BigInteger("1"), new BigInteger("4"), new BigInteger("5")};
        BigInteger userTSSIndex1 = new BigInteger("3");
        BigInteger serverIndex = new BigInteger("1");
        BigInteger coeff = TSSHelpers.getAdditiveCoefficient(true, participatingServerIndexes1, userTSSIndex1, serverIndex);
        BigInteger compare = new BigInteger("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", 16);
        assertEquals(coeff, compare);
    }

    @Test
    public void testGetDenormalizedCoefficient() {
        BigInteger party = new BigInteger("100");
        BigInteger[] parties = {new BigInteger("100"), new BigInteger("200")};
        BigInteger result = TSSHelpers.getDenormalizedCoefficient(party, List.of(parties));
        String expected = TSSHelpers.addLeadingZerosForLength64("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
        assertEquals(expected, result.toString(16));
    }

    @Test
    public void testGetDKLSCoefficient() throws TSSClientError {
        BigInteger[] participatingServerIndexes1 = {new BigInteger("1"), new BigInteger("4"), new BigInteger("5")};
        BigInteger userTssIndex1 = new BigInteger("3");
        BigInteger dklsCoeff = TSSHelpers.getDKLSCoefficient(true, List.of(participatingServerIndexes1), userTssIndex1, null);
        BigInteger compare = new BigInteger("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1", 16);
        assertTrue(dklsCoeff.equals(compare));

        BigInteger coeff2 = TSSHelpers.getDKLSCoefficient(false, List.of(new BigInteger[]{new BigInteger("1"), new BigInteger("2"), new BigInteger("5")}), new BigInteger("3"), new BigInteger("2"));
        BigInteger comp = new BigInteger("955555555555555555555555555555549790ab8690ea5d782fe561d2241fa611", 16);
        assertTrue(coeff2.equals(comp));

        BigInteger[] participatingServerIndexes = {new BigInteger("100"), new BigInteger("200")};
        BigInteger userTssIndex = new BigInteger("100");
        BigInteger result = TSSHelpers.getDKLSCoefficient(true, List.of(participatingServerIndexes), userTssIndex, null);
        String expected = TSSHelpers.addLeadingZerosForLength64("a57eb50295fad40a57eb50295fad40a4ac66b301bc4dfafaaa8d2b05b28fae1");
        assertEquals(expected, TSSHelpers.addLeadingZerosForLength64(result.toString(16)));

        //example related test
        BigInteger coeff01 = TSSHelpers.getDKLSCoefficient(false, Arrays.asList(
                new BigInteger("1"), new BigInteger("2"), new BigInteger("3")), new BigInteger("3"), new BigInteger("1"));
        BigInteger coeff02 = TSSHelpers.getDKLSCoefficient(false, Arrays.asList(
                new BigInteger("1"), new BigInteger("2"), new BigInteger("3")), new BigInteger("3"), new BigInteger("2"));
        BigInteger coeff03 = TSSHelpers.getDKLSCoefficient(false, Arrays.asList(
                new BigInteger("1"), new BigInteger("2"), new BigInteger("3")), new BigInteger("3"), new BigInteger("3"));
        assert coeff01.equals(new BigInteger("00dffffffffffffffffffffffffffffffee3590149d95f8c3447d812bb362f791a", 16));
        assert coeff02.equals(new BigInteger("003fffffffffffffffffffffffffffffffaeabb739abd2280eeff497a3340d9051", 16));
        assert coeff03.equals(new BigInteger("009fffffffffffffffffffffffffffffff34ad4a102d8d642557e37b180221e8c9", 16));

        BigInteger userCoeff2 = TSSHelpers.getDKLSCoefficient(true, Arrays.asList(
                new BigInteger("1"), new BigInteger("2"), new BigInteger("3")), new BigInteger("2"), null);
        BigInteger userCoeff3 = TSSHelpers.getDKLSCoefficient(true, Arrays.asList(
                new BigInteger("1"), new BigInteger("2"), new BigInteger("3")), new BigInteger("3"), null);
        assert userCoeff2.equals(new BigInteger("1", 16));
        assert userCoeff3.equals(new BigInteger("007fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1", 16));

        BigInteger[] participatingServerDKGIndexes = {new BigInteger("1"), new BigInteger("2"), new BigInteger("3")};
        String userCoeff22 = TSSHelpers.getClientCoefficients(participatingServerDKGIndexes, new BigInteger("2"));
        String userCoeff23 = TSSHelpers.getClientCoefficients(participatingServerDKGIndexes, new BigInteger("3"));
        assert TSSHelpers.removeLeadingZeros(userCoeff22).equals("1");
        assert TSSHelpers.removeLeadingZeros(userCoeff23).equals("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1");
    }

    @Test
    public void testFinalGetTSSPubkey() throws Exception {
        ByteBuffer dkgpubBuffer = ByteBuffer.allocate(1 + 32 + 32);
        dkgpubBuffer.put((byte) 0x04); // Uncompressed key prefix
        dkgpubBuffer.put(hexStringToByteArray(TSSHelpers.padLeft("18db3574e4217154769ad9cd88900e7f1c198aa60a1379f3869ba8a7699e6b53", '0', 64)));
        dkgpubBuffer.put(hexStringToByteArray(TSSHelpers.padLeft("d4f7d578667c38003f881f262e21655a38241401d9fc029c9a6fcbca8ac97713", '0', 64)));
        byte[] dkgpubBytes = dkgpubBuffer.array();

        ByteBuffer userpubBuffer = ByteBuffer.allocate(1 + 32 + 32);
        userpubBuffer.put((byte) 0x04); // Uncompressed key prefix
        userpubBuffer.put(hexStringToByteArray(TSSHelpers.padLeft("b4259bffab844a5255ba0c8f278b7fd857c094460b9051c95f04b29f9792368c", '0', 64)));
        userpubBuffer.put(hexStringToByteArray(TSSHelpers.padLeft("790eb133df835aa22fd087d5e33b26f2d2e046b6670ac7603500bc1227216247", '0', 64)));
        byte[] userpubBytes = userpubBuffer.array();

        BigInteger userTssIndex = new BigInteger("2");

        byte[] tssPub = TSSHelpers.getFinalTssPublicKey(dkgpubBytes, userpubBytes, userTssIndex);
        String expected = "04dd1619c7e99eb665e37c74828762e6a677511d4c52656ddc6499a57d486bddb8c0dc63b229ec9a31f4216138c3fbb67ac2630831135aecbaf0aafa095e439c61";
        assertEquals(expected, Hex.toHexString(tssPub));
    }

    // Helper function to convert hex strings to byte arrays
    private static byte[] hexStringToByteArray(String hexString) {
        int length = hexString.length();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return bytes;
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
        LinkedHashMap<String, String> coefficients_index3 = new LinkedHashMap<>();
        coefficients_index3.put("1", "1");
        coefficients_index3.put("2", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
        coefficients_index3.put("4", "dffffffffffffffffffffffffffffffee3590149d95f8c3447d812bb362f7919");

        Map<String, String> coeffs_index3 = TSSHelpers.getServerCoefficients(
                new BigInteger[]{new BigInteger("1"), new BigInteger("2"), new BigInteger("4")},
                new BigInteger("3")
        );

        assertEquals(coefficients_index3, coeffs_index3);

        LinkedHashMap<String, String> coefficients_index2 = new LinkedHashMap<>();
        coefficients_index2.put("1", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a2");
        coefficients_index2.put("2", "1");
        coefficients_index2.put("3", "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");

        Map<String, String> coeffs_index2 = TSSHelpers.getServerCoefficients(
                new BigInteger[]{new BigInteger("1"), new BigInteger("2"), new BigInteger("3")},
                new BigInteger("2")
        );

        assertEquals(coefficients_index2, coeffs_index2);
    }
}

