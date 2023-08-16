package com.web3auth.tss_client_android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.web3auth.tss_client_android.dkls.ChaChaRng;
import com.web3auth.tss_client_android.dkls.Counterparties;
import com.web3auth.tss_client_android.dkls.DKLSError;
import com.web3auth.tss_client_android.dkls.Precompute;
import com.web3auth.tss_client_android.dkls.SignatureFragments;
import com.web3auth.tss_client_android.dkls.ThresholdSigner;
import com.web3auth.tss_client_android.dkls.Utilities;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

@RunWith(AndroidJUnit4.class)
public class DklsTests {

    static {
        System.loadLibrary("dkls-native");
    }

    @BeforeClass
    public static void setupTest() {
    }

    @AfterClass
    public static void cleanTest() {
        System.gc();
    }

    @Test
    public void testRng() {
        try {
            ChaChaRng rng = new ChaChaRng();
        } catch (DKLSError | InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                 NoSuchProviderException e) {
            fail("Exception occurred: " + e.getLocalizedMessage());
        }
    }

    @Test
    public void testCounterparties() {
        String parties = "1,2";
        try {
            Counterparties counterparties = new Counterparties(parties);
            String export = counterparties.export();
            assertEquals(parties, export);
        } catch (DKLSError e) {
            fail("Exception occurred: " + e.getLocalizedMessage());
        }
    }

    @Test
    public void testSignatureFragments() {
        String input = "JLphVR9bO7pNnmL6dRQARixCwk3P07tsWu7TETIXNF0=,fcMuarM6YL0MR5j1kDxFw+q6OyKigW8n5sZnBGvzRZo=,BBJdnq8dFqFCXaiJZSiUzGANUDxlP8UXAenW9gfKLvk=";
        try {
            SignatureFragments fragments = new SignatureFragments(input);
            String export = fragments.export();
            assertEquals(input, export);
        } catch (DKLSError e) {
            fail("Exception occurred: " + e.getLocalizedMessage());
        }
    }

    @Test
    public void testUtilities() {
        try {
            String hashed = Utilities.hashEncode("Hello World");
            assertEquals(hashed, "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=");

            int batchSize = Utilities.batchSize();
            assertTrue(batchSize > 0);

            boolean hashOnly = true;
            String hash = "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=";
            String precomputeString = "TSbPQiau1tJoG6b2flNKXXb8EIGqgaAZ7PkuWJaNcKEGp8NkxS4XSrAF4gZlRmj4E+L9SOZ828DsusCUjUh8DA==#Q+aH50RJf1Aw2YHHyLc924drM8gqW9/lwxP5JTcejvM=#rkq/wFk2XPl3zv0XkHGyt4Duru9ao8zbmt6I4zorEXc=#vyx89I4ypkFtqi062u7xOCq35DZgwp6Gfo2VFoQpFzc=";
            Precompute precompute = new Precompute(precomputeString);
            String signatureFragment = Utilities.localSign(hash, hashOnly, precompute);
            assertEquals(signatureFragment, "JLphVR9bO7pNnmL6dRQARixCwk3P07tsWu7TETIXNF0=");

            String pubKey = "mbkxU1rQ0QkUzcFBUSSGh8TSaO2ndoHBXiIJexxa26DK430ZcOQIkYyWYgeRaIvyZo7oQliNd6PquEcIE2daUw==";
            SignatureFragments fragments = new SignatureFragments("JLphVR9bO7pNnmL6dRQARixCwk3P07tsWu7TETIXNF0=,fcMuarM6YL0MR5j1kDxFw+q6OyKigW8n5sZnBGvzRZo=,BBJdnq8dFqFCXaiJZSiUzGANUDxlP8UXAenW9gfKLvk=");
            String sig = Utilities.localVerify(hash, hashOnly, precompute, fragments, pubKey);
            assertEquals(sig, "TSbPQiau1tJoG6b2flNKXXb8EIGqgaAZ7PkuWJaNcKGmj+1egbKzGJxDpHlqeNrWdwpNrNeU76tDnxELpdSo8A==");
        } catch (DKLSError e) {
            fail("Exception occurred: " + e.getLocalizedMessage());
        }
    }

    @Test
    public void testPrecompute() {
        String input = "TSbPQiau1tJoG6b2flNKXXb8EIGqgaAZ7PkuWJaNcKEGp8NkxS4XSrAF4gZlRmj4E+L9SOZ828DsusCUjUh8DA==#Q+aH50RJf1Aw2YHHyLc924drM8gqW9/lwxP5JTcejvM=#rkq/wFk2XPl3zv0XkHGyt4Duru9ao8zbmt6I4zorEXc=#vyx89I4ypkFtqi062u7xOCq35DZgwp6Gfo2VFoQpFzc=";
        try {
            Precompute precompute = new Precompute(input);
            String r = precompute.getR();
            assertEquals(r, "TSbPQiau1tJoG6b2flNKXXb8EIGqgaAZ7PkuWJaNcKEGp8NkxS4XSrAF4gZlRmj4E+L9SOZ828DsusCUjUh8DA==");
            String export = precompute.export();
            assertEquals(input, export);
        } catch (DKLSError e) {
            fail("Exception occurred: " + e.getLocalizedMessage());
        }
    }

    @Test
    public void testThresholdSignerInit() {
        String session = "testingShares\u001ctest_verifier_name\u241ctest_verifier_id\u0015default\u00160\u0017577f8e058813e31d332c920ace5298b563c36d8d02d5c8cbce5b91621b7ef63etestingShares";
        int parties = 2;
        int threshold = 2;
        int index = 0;
        String share = "jLot8K2VTTJARiS7XCOuyYGE+rwsfNFFCq6CCyCdqSw=";
        String publicKey = "+AHtxLzwIRuzGFj/PZlgPpupyzqBvCn63nXjrWd6B9djE4NZL5b/HaHW/fGTxlfCa871n+FrkUnQhnSd3+ND7A==";
        try {
            ThresholdSigner signer = new ThresholdSigner(session, index, parties, threshold, share, publicKey);
        } catch (DKLSError e) {
            fail("Exception occurred: " + e.getLocalizedMessage());
        }
    }
}
