/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.tests.idmx;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Iterator;

import junit.framework.TestCase;

import com.ibm.zurich.credsystem.utils.Locations;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.MasterSecret;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.showproof.Prover;
import com.ibm.zurich.idmx.showproof.Verifier;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.Parser;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.XMLSerializer;

/**
 * Testing show-proofs. For each test there is first a specification created.
 * Using the specification the prover creates the proof and serializes it. The
 * verifier uses the specification and the proof and verifies the given
 * statement.
 */
public class TestProofCard extends TestCase {

    private MasterSecret masterSecret = null;

    /** Names of the Proof and Nonce objects. */
    private static final String CL_CARD = "clCardValues";

    public final static String ENDING = "\n "
            + "============================================================\n";
    public final static String PROOF_VERIFIED = "Proof Verified." + ENDING;

    /**
     * Performs the setup for the tests, i.e., loads the parameters and
     * instantiates the master secret.
     */
    protected final void setUp() {
        Locations.initSystem(TestIssuance.BASE_LOCATION,
                TestIssuance.BASE_ID.toString());

        // loading issuer public key
        Locations.init(TestIssuance.ISSUER_ID.resolve("ipk.xml"),
                TestIssuance.ISSUER_LOCATION.resolve("ipk.xml"));

        // loading credential structures
        preloadCredStructs();

        masterSecret = Locations.loadMasterSecret(TestIssuance.BASE_LOCATION
                .resolve("../private/ms.xml"));
    }

    private static final void loadCredStruct(String credStructName) {
        URI credStructLocation = null, credStructId = null;
        try {
            credStructLocation = TestIssuance.BASE_LOCATION
                    .resolve("../issuerData/" + credStructName + ".xml");
            credStructId = new URI("http://www.ngo.org/" + credStructName
                    + ".xml");
        } catch (URISyntaxException e1) {
            e1.printStackTrace();
        }

        // loading credential structure linked to a URI
        Locations.init(credStructId, credStructLocation);
    }

    /**
     * Loading all credential structures - required if they are not available at
     * the location indicated within the files (e.g., proof specification).
     */
    public static final void preloadCredStructs() {
        loadCredStruct(TestIssuanceCard.CRED_STRUCT_CARD);
        loadCredStruct(TestIssuance.CRED_STRUCT_0);
        loadCredStruct(TestIssuance.CRED_STRUCT_1A);
        loadCredStruct(TestIssuance.CRED_STRUCT_1B);
        loadCredStruct(TestIssuance.CRED_STRUCT_1C);
        loadCredStruct(TestIssuance.CRED_STRUCT_1D);
        loadCredStruct(TestIssuance.CRED_STRUCT_2);
        loadCredStruct(TestIssuance.CRED_STRUCT_3);
        loadCredStruct(TestIssuance.CRED_STRUCT_4);
        loadCredStruct(TestIssuance.CRED_STRUCT_5);
        loadCredStruct(TestIssuance.CRED_STRUCT_6);
    }

    /**
     * @param credUri
     *            File name of the credential.
     * @param tempCredName
     *            Temporary name of the credential in the proof specification.
     * @return Map with credentials that will be needed for the proof.
     */
    public final static HashMap<String, Credential> loadCredential(URI credUri,
            String tempCredName) {

        final Credential c = (Credential) Parser.getInstance().parse(credUri);
        if (c == null) {
            fail("getting credential");
        }

        HashMap<String, Credential> creds = new HashMap<String, Credential>();
        String credTempName = c.getCredStructId().toString()
                .concat(Constants.DELIMITER).concat(tempCredName);
        creds.put(credTempName, c);
        return creds;
    }

    /**
     * Test: Reads the library version and fails if the version is not the
     * expected version.
     */
    public final void testVersion() {
        if (Constants.getVersion() != "2.3.4") {
            fail("wrong version");
        }
    }

    /**
     * Convenience method.
     */
    private final String getProofLocation(String name) {
        return "../send/" + name + "_proof.xml";
    }

    /**
     * Convenience method.
     */
    private final String getNonceLocation(String name) {
        return "../send/" + name + "_nonce.xml";
    }

    /**
     * Convenience method.
     */
    private void serializeElements(String name, Proof p, BigInteger nonce) {
        // save the proof
        XMLSerializer.getInstance().serialize(p,
                TestIssuance.BASE_LOCATION.resolve(getProofLocation(name)));
        // save the nonce for the verification test case
        XMLSerializer.getInstance().serialize(nonce,
                TestIssuance.BASE_LOCATION.resolve(getNonceLocation(name)));
    }

    /**
     * Test: Builds a proof according to the specification.
     * 
     * @see TestIssuance#testIssuance_CredCard_knownValues()
     */
    public final void testProve_CredCard() {

        // load the proof specification
        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
                TestIssuance.BASE_LOCATION
                        .resolve("../proofSpecifications/ProofSpecCard.xml"));
        System.out.println(spec.toStringPretty());

        SystemParameters sp = spec.getGroupParams().getSystemParams();

        // first get the nonce (done by the verifier)
        System.out.println("Getting nonce.");
        BigInteger nonce = Verifier.getNonce(sp);

        // load credentials
        HashMap<String, Credential> creds = loadCredential(
                TestIssuance.BASE_LOCATION.resolve("../private/"
                        + TestIssuanceCard.CREDCARD_FN + ".xml"), "someRandomName");

        Prover prover = new Prover(masterSecret, creds);
        // create the proof
        Proof p = prover.buildProof(nonce, spec);
        System.out.println("Proof Created.");

        serializeElements(CL_CARD, p, nonce);
    }

    /**
     * Test: Verifies the proof according to the specification.
     * 
     * @see TestProofCard#testProve_CredCard()
     */
    public final void testVerify_CredCard() {

        // load the proof specification
        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
                TestIssuance.BASE_LOCATION
                        .resolve("../proofSpecifications/ProofSpecCard.xml"));
        System.out.println(spec.toStringPretty());

        // load the proof
        Proof p = (Proof) Parser.getInstance().parse(
                TestIssuance.BASE_LOCATION.resolve(getProofLocation(CL_CARD)));
        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
                TestIssuance.BASE_LOCATION.resolve(getNonceLocation(CL_CARD)));

        // now p is sent to the verifier
        Verifier verifier = new Verifier(spec, p, nonce);
        if (!verifier.verify()) {
            fail("The proof does not verify");
        } else {
            System.out.println(PROOF_VERIFIED);
        }

        // shows the values that have been revealed during the proof
        HashMap<String, BigInteger> revealedValues = verifier
                .getRevealedValues();
        outputRevealedValues(revealedValues);
    }

    /**
     * @param revealedValues
     */
    private static final void outputRevealedValues(
            HashMap<String, BigInteger> revealedValues) {
        Iterator<String> it = revealedValues.keySet().iterator();
        System.out.println("Revealed values...");
        while (it.hasNext()) {
            String key = it.next();
            System.out.println("\t" + key + "\t"
                    + Utils.logBigInt(revealedValues.get(key)));
        }
        System.out.println(ENDING);
    }
}
