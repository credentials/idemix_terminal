package org.irmacard.credentials.idemix;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;

import javax.smartcardio.CardException;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.descriptions.IdemixVerificationDescription;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.idemix.smartcard.IRMACard;
import org.irmacard.credentials.idemix.smartcard.SmartCardEmulatorService;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.DescriptionStoreDeserializer;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.idemix.IdemixService;
import org.irmacard.idemix.IdemixSmartcard;
import org.irmacard.idemix.util.CardVersion;
import org.junit.BeforeClass;
import org.junit.Test;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ProtocolCommand;
import net.sf.scuba.smartcards.ProtocolCommands;
import net.sf.scuba.smartcards.ProtocolResponse;

/**
 * Directly run a few test cases on the simulated card. In particular,
 * test some of the security conditions of the card.
 *
 * TODO: this test suite is not complete
 */
public class TestCard {
    @BeforeClass
    public static void initializeInformation() throws InfoException {
        URI core = new File(System
                .getProperty("user.dir")).toURI()
                .resolve("irma_configuration/");
        DescriptionStore.initialize(new DescriptionStoreDeserializer(core));
        IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(core));
    }

    private CardService getCardService() {
        return new SmartCardEmulatorService(new IRMACard());
    }

    @Test
    public void issueCredential() throws InfoException, CardException,
            CredentialsException, CardServiceException {
        TestCardHelpers.issue("Surfnet", "root", getSurfnetAttributes(),
                getCardService());
    }

    @Test
    public void issueVerifyCredential() throws InfoException, CardException,
            CredentialsException, CardServiceException {
        CardService cs = getCardService();
        TestCardHelpers.issue("Surfnet", "root", getSurfnetAttributes(), cs);
        verify("Surfnet", "rootAll", cs);
    }

    /**
     * Test a security condition on the card, it should report an
     * error when the reader requests too many attributes for a
     * given credential.
     * @throws InfoException
     * @throws CardServiceException
     * @throws CredentialsException
     * @throws CardException
     */
    @Test
    public void verifyAskTooManyAttributes() throws InfoException, CardException, CredentialsException, CardServiceException {
        CardService cs = getCardService();
        IdemixService service = new IdemixService(cs);

        // First issue a credential
        TestCardHelpers.issue("Surfnet", "root", getSurfnetAttributes(), cs);
        service.open();

        // No we will asynchronously verify this credential (so that we can
        // inject some commands
        IssuerIdentifier verifierId = new IssuerIdentifier(TestIRMACredential.schemeManager, "Surfnet");
        IdemixVerificationDescription vd =
                new IdemixVerificationDescription(verifierId, "rootNone");

        // Select applet and process version
        ProtocolResponse select_response = service.execute(
                IdemixSmartcard.selectApplicationCommand);
        CardVersion cv = new CardVersion(select_response.getData());

        // Generate a nonce (you need this for verification as well)
        BigInteger nonce = vd.generateNonce();

        // Get prove commands, and send them to card
        ProtocolCommands commands = IdemixSmartcard
                .buildProofCommands(cv, nonce, vd);

        // *** This is where the magic happens ***
        // Craft a command for an extra attribute
        int fail_idx = vd.getVerificationDescription().getCredentialDescription()
                .getAttributes().size() + 2;
        System.out.println(commands.get(commands.size() - 1));
        ProtocolCommand extra_attribute = new ProtocolCommand("attr_extra",
                "Command should fail", new CommandAPDU(IdemixSmartcard.CLA_IRMACARD,
                        IdemixSmartcard.INS_PROVE_ATTRIBUTE, fail_idx, 0x00));
        commands.add(extra_attribute);

        // This should fail
        boolean failed = false;
        try {
            service.execute(commands);
        } catch (CardServiceException e) {
            e.printStackTrace();
            assertEquals(e.getSW(), ISO7816.SW_WRONG_P1P2);
            failed = true;
        }
        assertTrue("Excecute should throw an exception", failed);
    }

    private void verify(String verifier, String verification_spec, CardService cs)
            throws CardException, CredentialsException, InfoException {
        Attributes attr = TestCardHelpers.verify(verifier, verification_spec, cs);
        if (attr == null) {
            fail("The proof does not verify");
        }
    }

    private Attributes getSurfnetAttributes() {
        Attributes attributes = new Attributes();

        attributes.add("userID", "s1234567@student.ru.nl".getBytes());
        attributes.add("securityHash", "DEADBEEF".getBytes());

        return attributes;
    }

}
