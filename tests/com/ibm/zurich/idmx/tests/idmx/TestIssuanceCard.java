/**
 * Copyright IBM Corporation 2009-2011.
 */
package com.ibm.zurich.idmx.tests.idmx;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import junit.framework.TestCase;
import net.sourceforge.scuba.smartcards.TerminalCardService;

import org.irmacard.idemix.IdemixService;

import com.ibm.zurich.credsystem.utils.Locations;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.issuance.Issuer;
import com.ibm.zurich.idmx.issuance.Message;
import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.utils.Constants;

/**
 * Test cases to cover issuance of credentials.
 */
public class TestIssuanceCard extends TestCase {

    /** Actual location of the files. */
    public static final URI BASE_LOCATION = new File(
            System.getProperty("user.dir")).toURI().resolve("files/parameter/");

    /** Id that is used within the test files to identify the elements. */
    public static URI BASE_ID = null;
    /** Id that is used within the test files to identify the elements. */
    public static URI ISSUER_ID = null;
    static {
        try {
            BASE_ID = new URI("http://www.zurich.ibm.com/security/idmx/v2/");
            ISSUER_ID = new URI("http://www.issuer.com/");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
    /** Actual location of the public issuer-related files. */
    public static final URI ISSUER_LOCATION = BASE_LOCATION
            .resolve("../issuerData/");

    /** Attribute value 1313. */
    public static final BigInteger ATTRIBUTE_VALUE_1 = BigInteger.valueOf(1313);
    /** Attribute value 1314. */
    public static final BigInteger ATTRIBUTE_VALUE_2 = BigInteger.valueOf(1314);
    /** Attribute value 1315. */
    public static final BigInteger ATTRIBUTE_VALUE_3 = BigInteger.valueOf(1315);
    /** Attribute value 1316. */
    public static final BigInteger ATTRIBUTE_VALUE_4 = BigInteger.valueOf(1316);
    /** Attribute value 1317. */
    public static final BigInteger ATTRIBUTE_VALUE_5 = BigInteger.valueOf(1317);

    /**
     * Credential structure.
     * <ol>
     * <li>attr1: known: int</li>
     * <li>attr2: known: int</li>
     * <li>attr3: known: int</li>
     * <li>attr4: known: int</li>
     * <li>attr5: known: int</li>
     * </ol>
     */
    public static final String CRED_STRUCT_CARD = "CredStructCard4";

    /**
     * Credential.<br/>
     * <ol>
     * <li>attr1:1313/ATTRIBUTE_VALUE_1</li>
     * <li>attr2:1314/ATTRIBUTE_VALUE_2</li>
     * <li>attr3:1315/ATTRIBUTE_VALUE_3</li>
     * <li>attr4:1316/ATTRIBUTE_VALUE_4</li>
     * <li>attr5:1317/ATTRIBUTE_VALUE_5</li>
     * </ol>
     * 
     * @see TestIssuanceCard#CRED_STRUCT_CARD
     */
    public static final String CREDCARD_FN = "Credential_card";    

    /** Key pair of the issuer. */
    private IssuerKeyPair issuerKey = null;

    /**
     * Setup of the test environment.
     */
    protected final void setUp() {
        
        // URIs and locations for issuer
        URI iskLocation = BASE_LOCATION.resolve("../private/isk.xml");
        URI ipkLocation = ISSUER_LOCATION.resolve("ipk.xml");

        issuerKey = Locations.initIssuer(BASE_LOCATION, BASE_ID.toString(),
                iskLocation, ipkLocation, ISSUER_ID.resolve("ipk.xml"));
    }

    /**
     * Executed upon finishing the test run.
     */
    protected final void tearDown() {}

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
     * Test: Issues a credential.
     * 
     * @see TestIssuanceCard#CRED_STRUCT_CARD
     * @see TestIssuanceCard#CREDCARD_FN
     */
    public final void testIssuance_CredCard() {
        String credStruct = TestIssuanceCard.CRED_STRUCT_CARD;

        // URIs and locations for recipient
        URI credStructLocation = null, credStructId = null;
        try {
            credStructLocation = BASE_LOCATION.resolve("../issuerData/"
                    + credStruct + ".xml");
            credStructId = new URI("http://www.ngo.org/" + credStruct + ".xml");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        // loading credential structure linked to a URI
        Locations.init(credStructId, credStructLocation);

        // create the issuance specification
        IssuanceSpec issuanceSpec = new IssuanceSpec(
                ISSUER_ID.resolve("ipk.xml"), credStructId);

        // get the values - NOTE: the values are KNOWN to both parties (as
        // specified in the credential structure)
        Values values = new Values(issuerKey.getPublicKey().getGroupParams()
                .getSystemParams());
        values.add("attr1", ATTRIBUTE_VALUE_1);
        values.add("attr2", ATTRIBUTE_VALUE_2);
        values.add("attr3", ATTRIBUTE_VALUE_3);
        values.add("attr4", ATTRIBUTE_VALUE_4);
//        values.add("attr5", ATTRIBUTE_VALUE_5);

        // run the issuance protocol.
        Issuer issuer = new Issuer(issuerKey, issuanceSpec, null, null, values);

        IdemixService recipient = null;
        try {
            CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);            
            recipient = new IdemixService(new TerminalCardService(terminal), (short)4);
            recipient.open();
            recipient.generateMasterSecret();
            recipient.setIssuanceSpecification(issuanceSpec);
            recipient.setAttributes(issuanceSpec, values);
        } catch (Exception e) {
            fail(e.getMessage()); 
            e.printStackTrace();            
        }
         
        Message msgToRecipient1 = issuer.round0();
        if (msgToRecipient1 == null) {
            fail("round0");
        }

        Message msgToIssuer1 = recipient.round1(msgToRecipient1);
        if (msgToIssuer1 == null) {
            fail("round1");
        }

        Message msgToRecipient2 = issuer.round2(msgToIssuer1);
        if (msgToRecipient2 == null) {
            fail("round2");
        }

        recipient.round3(msgToRecipient2);
    }
}
