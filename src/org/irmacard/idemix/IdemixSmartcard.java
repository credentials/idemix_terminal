/**
 * IRMASmartcard.java
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, June 2011.
 */

package org.irmacard.idemix;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.ISO7816;
import net.sourceforge.scuba.smartcards.ProtocolCommand;
import net.sourceforge.scuba.smartcards.ProtocolCommands;
import net.sourceforge.scuba.smartcards.ProtocolErrors;
import net.sourceforge.scuba.smartcards.ProtocolResponses;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.descriptions.IdemixCredentialDescription;
import org.irmacard.credentials.idemix.descriptions.IdemixVerificationDescription;
import org.irmacard.credentials.idemix.irma.IRMAIdemixDisclosureProof;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofU;
import org.irmacard.idemix.util.CardVersion;
import org.irmacard.idemix.util.IdemixFlags;
import org.irmacard.idemix.util.IssuanceSetupData;
import org.irmacard.idemix.util.VerificationSetupData;

/**
 * Idemix Smart Card Interface based on a SCUBA Card Service.
 *
 * @author Pim Vullers
 * @version $Revision: 554 $ by $Author: pim $
 *          $LastChangedDate: 2011-04-28 16:31:47 +0200 (Thu, 28 Apr 2011) $
 */
public class IdemixSmartcard {

    /**
     * AID of the IRMAcard application: ASCII encoding of "IRMAcard".
     */
    public static final byte[] AID = {(byte) 0xF8, 0x49, 0x52, 0x4D, 0x41, 0x63, 0x61, 0x72, 0x64};
    public static final byte[] AID_0_7 = {0x49, 0x52, 0x4D, 0x41, 0x63, 0x61, 0x72, 0x64};

    /**
     * INStruction to select an application.
     */
    public static final byte INS_SELECT_APPLICATION = (byte) 0xA4;

    /**
     * P1 parameter for select by name.
     */
    public static final byte P1_SELECT_BY_NAME = 0x04;


    /**
     * CLAss to be used for IRMA APDUs.
     */
    public static final byte CLA_IRMACARD = (byte) 0x80;

    /**
     * CLAss mask to indicate command chaining.
     */
    public static final byte CLA_COMMAND_CHAINING = 0x10;

    /**
     * INStruction to generate the master secret on the card.
     */
    public static final byte INS_GENERATE_SECRET = 0x01;

    /**
     * INStruction to generate the master secret on the card.
     */
    public static final byte INS_AUTHENTICATION_SECRET = 0x02;

    /**
     * INStruction to start issuing a credential (and to set the corresponding
     * context and issuance information).
     */
    public static final byte INS_ISSUE_CREDENTIAL = 0x10;

    /**
     * INStruction to issue the the issuer public key.
     */
    public static final byte INS_ISSUE_PUBLIC_KEY = 0x11;

    /**
     * INStruction to issue the attributes.
     */
    public static final byte INS_ISSUE_ATTRIBUTES = 0x12;

    /**
     * combined hidden attributes (U).
     */
    public static final byte INS_ISSUE_COMMITMENT = 0x1A;

    /**
     * INStruction to receive the zero-knowledge proof for correct construction
     * of U (c, v^', s_A).
     */
    public static final byte INS_ISSUE_COMMITMENT_PROOF = 0x1B;

    /**
     * INStruction to receive the second nonce (n_2).
     */
    public static final byte INS_ISSUE_CHALLENGE = 0x1C;

    /**
     * INStruction to send the blind signature (A, e, v'').
     */
    public static final byte INS_ISSUE_SIGNATURE = 0x1D;

    /**
     * INStruction to verify the signature and the zero-knowledge proof.
     */
    public static final byte INS_ISSUE_VERIFY = 0x1F;

    /**
     * INStruction to start proving attributes from a credential (and to set
     * the corresponding context).
     */
    public static final byte INS_PROVE_CREDENTIAL = 0x20;

    /**
     * INStruction to send the challenge (m) to be signed in the proof and
     * receive the commitment for the proof (a).
     */
    public static final byte INS_PROVE_COMMITMENT = 0x2A;

    /**
     * INStruction to receive the values A', e^ and v^.
     */
    public static final byte INS_PROVE_SIGNATURE = 0x2B;

    /**
     * INStruction to receive the disclosed attributes (A_i).
     */
    public static final byte INS_PROVE_ATTRIBUTE = 0x2C;

    /**
     * INStruction to select a credential on the card.
     */
    public static final byte INS_ADMIN_CREDENTIAL = 0x30;

    /**
     * INStruction to remove a credential from the card.
     */
    public static final byte INS_ADMIN_REMOVE = 0x31;

    /**
     * INStruction to get an attribute from the current selected credential.
     */
    public static final byte INS_ADMIN_ATTRIBUTE = 0x32;

    /**
     * INStruction to get the flags of a credential.
     */
    public static final byte INS_ADMIN_FLAGS = 0x33;

    /**
     * INStruction to get a list of credentials stored on the card.
     */
    public static final byte INS_ADMIN_CREDENTIALS = 0x3A;

    /**
     * INStruction to get the transaction log from the card.
     */
    public static final byte INS_ADMIN_LOG = 0x3B;


    /**
     * P1 parameter for the n value from the issuer public key.
     */
    public static final byte P1_PUBLIC_KEY_N = 0x00;

    /**
     * P1 parameter for the s value from the issuer public key.
     */
    public static final byte P1_PUBLIC_KEY_S = 0x01;

    /**
     * P1 parameter for the z value from the issuer public key.
     */
    public static final byte P1_PUBLIC_KEY_Z = 0x02;

    /**
     * P1 parameter for the R values from the issuer public key.
     */
    public static final byte P1_PUBLIC_KEY_R = 0x03;

    /**
     * P1 parameter for the A value from a signature.
     */
    public static final byte P1_SIGNATURE_A = 0x01;

    /**
     * P1 parameter for the e value from a signature.
     */
    public static final byte P1_SIGNATURE_E = 0x02;

    /**
     * P1 parameter for the v value from a signature.
     */
    public static final byte P1_SIGNATURE_V = 0x03;

    /**
     * P1 parameter for the challenge of a proof.
     */
    public static final byte P1_SIGNATURE_PROOF_C = 0x04;

    /**
     * P1 parameter for the s_e response of a proof.
     */
    public static final byte P1_SIGNATURE_PROOF_S_E = 0x05;

    /**
     * P1 parameter for the challenge of a proof.
     */
    public static final byte P1_PROOF_C = 0x01;

    /**
     * P1 parameter for the vPrimeHat response of a proof.
     */
    public static final byte P1_PROOF_VPRIMEHAT = 0x02;

    /**
     * P1 parameter for the sHat response of a proof.
     */
    public static final byte P1_PROOF_SHAT = 0x03;

    /**
     * P1 parameter for the modulus of an RSA key.
     */
    public static final byte P1_RSA_MODULUS = 0x00;

    /**
     * P1 parameter for the exponent of an RSA key.
     */
    public static final byte P1_RSA_EXPONENT = 0x01;

    /**
     * P2 parameter for the attribute PIN.
     */
    public static final byte P2_PIN_ATTRIBUTE = 0x00;

    /**
     * P2 parameter for the administrative PIN.
     */
    public static final byte P2_PIN_ADMIN = 0x01;

    /**
     * Values for backward-compatibility with older cards.
     */
    private static final byte INS_ISSUE_SIGNATURE_0_7 = 0x1D;
    private static final byte INS_ISSUE_SIGNATURE_PROOF_0_7 = 0x1E;
    private static final byte P1_SIGNATURE_VERIFY_0_7 = 0x00;
    private static final byte P1_PROOF_VERIFY_0_7 = 0x00;
    private static final byte P1_PROOF_C_0_7 = 0x01;
    private static final byte P1_PROOF_S_E_0_7 = 0x04;
    /**
     * Produces an unsigned byte-array representation of a BigInteger.
     *
     * <p>BigInteger adds an extra sign bit to the beginning of its byte
     * array representation.  In some cases this will cause the size
     * of the byte array to increase, which may be unacceptable for some
     * applications. This function returns a minimal byte array representing
     * the BigInteger without extra sign bits.
     *
     * <p>This method is taken from the Network Security Services for Java (JSS)
     * currently maintained by the Mozilla Foundation and originally developed
     * by the Netscape Communications Corporation.
     *
     * @return unsigned big-endian byte array representation of a BigInteger.
     */
    public static byte[] BigIntegerToUnsignedByteArray(BigInteger big) {
        byte[] ret;

        // big must not be negative
        assert(big.signum() != -1);

        // bitLength is the size of the data without the sign bit.  If
        // it exactly fills an integral number of bytes, that means a whole
        // new byte will have to be added to accommodate the sign bit. In
        // this case we need to remove the first byte.
        if(big.bitLength() % 8 == 0) {
            byte[] array = big.toByteArray();
            // The first byte should just be sign bits
            assert( array[0] == 0 );
            ret = new byte[array.length-1];
            System.arraycopy(array, 1, ret, 0, ret.length);
        } else {
            ret = big.toByteArray();
        }
        return ret;
    }

    /**
     * Fix the length of array representation of BigIntegers put into the APDUs.
     *
     * @param integer of which the length needs to be fixed.
     * @param the new length of the integer in bits
     * @return an array with a fixed length.
     */
    public static byte[] fixLength(BigInteger integer, int length_in_bits) {
        byte[] array = BigIntegerToUnsignedByteArray(integer);
        int length;

        length = length_in_bits/8;
        if (length_in_bits % 8 != 0){
            length++;
        }

        assert (array.length <= length);

        int padding = length - array.length;
        byte[] fixed = new byte[length];
        Arrays.fill(fixed, (byte) 0x00);
        System.arraycopy(array, 0, fixed, padding, array.length);
        return fixed;
    }

    private static byte[] addTimeStamp(byte[] argument) {
        int time = getTimeStamp();
        return ByteBuffer.allocate(argument.length + 4).put(argument)
                .putInt(time).array();
    }

    private static int getTimeStamp() {
    	return (int) ((new Date()).getTime() / 1000);
    }

    /**************************************************************************/
    /* IRMAcard Smart Card commands                                           */
    /**************************************************************************/

    public static ProtocolCommand selectApplicationCommand =
            new ProtocolCommand(
                    "selectapplet",
                    "Select IRMAcard application",
                     new CommandAPDU(ISO7816.CLA_ISO7816,
                                INS_SELECT_APPLICATION, P1_SELECT_BY_NAME, 0x00, AID, 256)); // LE == 0 is required.
    public static ProtocolCommand selectApplicationCommand_0_7 =
            new ProtocolCommand(
                    "selectapplet",
                    "Select IRMAcard application",
                     new CommandAPDU(ISO7816.CLA_ISO7816,
                                INS_SELECT_APPLICATION, P1_SELECT_BY_NAME, 0x00, AID_0_7, 256)); // LE == 0 is required.

    /**
     * Get the APDU commands for setting the specification of
     * a certificate issuance:
     * <ul>
     *   <li> issuer public key, and
     *   <li> context.
     * </ul>
     *
     * @param spec the specification to be set
     * @param id
     * @return
     */
	public static ProtocolCommands setIssuanceSpecificationCommands(
			CardVersion cv, IdemixCredentialDescription cd) {
        ProtocolCommands commands = new ProtocolCommands();
        commands.add(startIssuanceCommand(cv, cd));
        commands.addAll(setPublicKeyCommands(cv, cd));
        return commands;
    }

    /**
     * Get the APDU commands for setting the public key on
     * the card.
     *
     * @param spec Issuance spec to get the public key from.
     * @return
     */
	public static ProtocolCommands setPublicKeyCommands(CardVersion cv,
			IdemixCredentialDescription cd) {
		IdemixPublicKey pk = cd.getPublicKey();
		int l_n = pk.getSystemParameters().l_n;

        ProtocolCommands commands = new ProtocolCommands();
        commands.add(
                new ProtocolCommand(
                        "publickey_n",
                        "Set public key (n)",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_PUBLIC_KEY, P1_PUBLIC_KEY_N, 0x00,
                                fixLength(pk.getModulus(), l_n))));

        commands.add(
                new ProtocolCommand(
                        "publickey_z",
                        "Set public key (Z)",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_PUBLIC_KEY, P1_PUBLIC_KEY_Z, 0x00,
                                fixLength(pk.getGeneratorZ(), l_n))));

        commands.add(
                new ProtocolCommand(
                        "publickey_s",
                        "Set public key (S)",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_PUBLIC_KEY, P1_PUBLIC_KEY_S, 0x00,
                                fixLength(pk.getGeneratorS(), l_n))));

        List<BigInteger> generatorsR = pk.getGeneratorsR();
        for (int i = 0; i <= cd.numberOfAttributes(); i++) {
            commands.add(
                    new ProtocolCommand(
                            "publickey_element" + i,
                            "Set public key element (R@index " + i + ")",
                            new CommandAPDU(
                                    CLA_IRMACARD, INS_ISSUE_PUBLIC_KEY, P1_PUBLIC_KEY_R, i,
                                    fixLength(generatorsR.get(i), l_n))));
        }

        return commands;
    }


    /**
     * Get the APDU commands to start issuance.
     *
     * @param spec Issuance specification
     * @param id id of credential
     * @return
     */
    public static ProtocolCommand startIssuanceCommand(CardVersion cv, IdemixCredentialDescription cd) {
    	int l_H = cd.getPublicKey().getSystemParameters().l_h;

    	// FIXME: flags set to 0 for now
    	IdemixFlags flags = new IdemixFlags();

		IssuanceSetupData isd = new IssuanceSetupData(cd
				.getCredentialDescription().getId(),
				(short) cd.numberOfAttributes(), flags, cd.getContext(),
				getTimeStamp());

        return new ProtocolCommand(
                                "start_issuance",
                                "Start credential issuance.",
                                new CommandAPDU(
                                    CLA_IRMACARD, INS_ISSUE_CREDENTIAL, 0x00, 0x00, isd.getBytes(cv)),
                        new ProtocolErrors(
                                    0x00006986,"Credential already issued."));
    }

    /**
     * Get the APDU commands to start proof.
     *
     * @param spec Proof specification
     * @param id id of credential
     * @return
     */
	public static ProtocolCommand startProofCommand(CardVersion cv,
			IdemixVerificationDescription vd) {
		byte[] data = new VerificationSetupData(vd, getTimeStamp())
				.getBytes(cv);

		return new ProtocolCommand("startprove", "Start credential proof.",
				new CommandAPDU(CLA_IRMACARD, INS_PROVE_CREDENTIAL, 0x00, 0x00,
						data), new ProtocolErrors(0x00006A88,
						"Credential not found."));
	}

    public static ProtocolCommands generateMasterSecretCommand(CardVersion cv) {
        ProtocolCommands commands = new ProtocolCommands();

        if (!cv.newer(new CardVersion(0,7,2))) {
            commands.add(new ProtocolCommand(
                        "generatesecret",
                        "Generate master secret",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_GENERATE_SECRET, 0x00, 0x00),
                        new ProtocolErrors(
                                0x00006986,"Master secret already set.")));
        }

        return commands;
    }

    public static ProtocolCommands initialiseAuthenticationKey(CardVersion cv, RSAPrivateKey key) {
        ProtocolCommands commands = new ProtocolCommands();

        if (!cv.older(new CardVersion(0,8))) {
            commands.add(new ProtocolCommand(
                    "initauthmod",
                    "Initialise the RSA modulus of the authentication key",
                    new CommandAPDU(
                            CLA_IRMACARD, INS_AUTHENTICATION_SECRET, P1_RSA_MODULUS, 0x00,
                            fixLength(key.getModulus(), 128))
                    ));

            commands.add(new ProtocolCommand(
                    "initauthexp",
                    "Initialise the RSA exponent of the authentication key",
                    new CommandAPDU(
                            CLA_IRMACARD, INS_AUTHENTICATION_SECRET, P1_RSA_EXPONENT, 0x00,
                            fixLength(key.getPrivateExponent(), 128))
                    ));
        }

        return commands;
    }

    public static ProtocolCommand sendPinCommand(CardVersion cv, byte pinID, byte[] pin) {
        byte[] pinBytes = new byte[8];
        System.arraycopy(pin, 0, pinBytes, 0, pin.length);

        return new ProtocolCommand(
                        "sendpin",
                        "Authorize using PIN",
                        new CommandAPDU(
                                ISO7816.CLA_ISO7816, ISO7816.INS_VERIFY, 0x00, pinID, pinBytes)
                        );
    }

    public static ProtocolCommands queryPinCommand(CardVersion cv, byte pinID) {
        ProtocolCommands commands = new ProtocolCommands();

        if (cv.newer(new CardVersion(0, 7, 2))) {
            commands.add(new ProtocolCommand(
                        "querypin",
                        "Query PIN verification status",
                        new CommandAPDU(
                                ISO7816.CLA_ISO7816, ISO7816.INS_VERIFY, 0x00, pinID)
                        ));
        }

        return commands;
    }

    public static ProtocolCommands updatePinCommand(CardVersion cv, byte pinID, byte[] oldPin, byte[] newPin) {
        ProtocolCommands commands = new ProtocolCommands();
        byte[] pinBytes;
        if (cv.newer(new CardVersion(0,7,2))) {
            if (pinID == P2_PIN_ADMIN) {
                pinBytes = new byte[16];
                System.arraycopy(oldPin, 0, pinBytes, 0, oldPin.length);
                System.arraycopy(newPin, 0, pinBytes, 8, newPin.length);
            } else {
                pinBytes = new byte[8];
                System.arraycopy(newPin, 0, pinBytes, 0, newPin.length);
            }
        } else {
            pinBytes = new byte[16];
            System.arraycopy(oldPin, 0, pinBytes, 0, oldPin.length);
            System.arraycopy(newPin, 0, pinBytes, 8, newPin.length);
        }
        commands.add(
                new ProtocolCommand(
                        "updatepin",
                        "Update current PIN",
                        new CommandAPDU(
                                ISO7816.CLA_ISO7816, ISO7816.INS_CHANGE_CHV, 0x00, pinID, pinBytes)
                        ));
        return commands;
    }

    /**
     * Get the APDU commands for setting the attributes:
     *
     * <pre>
     *   m_1, ..., m_l
     * </pre>
     *
     * @param spec the issuance specification for the ordering of the values.
     * @param values the attributes to be set.
     * @return
     */
    public static ProtocolCommands setAttributesCommands(CardVersion cv, IdemixCredentialDescription cd, Attributes attributes) {
        ProtocolCommands commands = new ProtocolCommands();
        int L_m = cd.getPublicKey().getSystemParameters().l_m;

        attributes.print();
        System.out.println(cd.getCredentialDescription().getAttributeNames());

        for (int i = 1; i <= cd.numberOfAttributes(); i++) {
        	BigInteger attr = new BigInteger(1, attributes.get(cd.getAttributeName(i)));
            commands.add(
                    new ProtocolCommand(
                            "setattr"+i,
                            "Set attribute (m@index" + i + ")",
                            new CommandAPDU(
                                    CLA_IRMACARD, INS_ISSUE_ATTRIBUTES, i, 0x00,
                                    fixLength(attr, L_m))));
        }
        return commands;
    }

	public static ProtocolCommands requestCommitmentCommands(CardVersion cv,
			IdemixCredentialDescription cd, BigInteger nonce1) {
		ProtocolCommands commands = new ProtocolCommands();
        int l_statzk = cd.getPublicKey().getSystemParameters().l_statzk;
        commands.add(
                new ProtocolCommand(
                        "nonce_n1",
                        "Issue nonce n1",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_COMMITMENT, 0x00, 0x00,
                                fixLength(nonce1, l_statzk))));
        commands.add(
                new ProtocolCommand(
                        "proof_c",
                        "Issue proof c",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_COMMITMENT_PROOF, P1_PROOF_C, 0x00)));

        commands.add(
                new ProtocolCommand(
                        "vHatPrime",
                        "Issue proof v^'",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_COMMITMENT_PROOF, P1_PROOF_VPRIMEHAT, 0x00)));
        commands.add(
                new ProtocolCommand(
                        "proof_s_A",
                        "Issue proof s_A",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_COMMITMENT_PROOF, P1_PROOF_SHAT, 0x00)));
        commands.add(
                new ProtocolCommand(
                        "nonce_n2",
                        "Issue nonce n2",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_CHALLENGE, 0x00, 0x00)));
        return commands;
    }

	public static ProtocolCommands requestIssueCommitmentCommands(
			CardVersion cv, IdemixCredentialDescription cd,
			Attributes attributes, BigInteger nonce1) {
		ProtocolCommands commands = new ProtocolCommands();
		commands.addAll(
			IdemixSmartcard.setIssuanceSpecificationCommands(cv, cd));
		commands.addAll(
			IdemixSmartcard.setAttributesCommands(cv, cd, attributes));
		commands.addAll(
			IdemixSmartcard.requestCommitmentCommands(cv, cd, nonce1));
		return commands;
	}

	public static IssueCommitmentMessage processIssueCommitmentCommands(
			CardVersion cv, ProtocolResponses responses) {
		BigInteger U =
				new BigInteger(1, responses.get("nonce_n1").getData());
		BigInteger c =
				new BigInteger(1, responses.get("proof_c").getData());
		BigInteger v_prime_response =
				new BigInteger(1, responses.get("vHatPrime").getData());
		BigInteger s_response =
				new BigInteger(1, responses.get("proof_s_A").getData());
		BigInteger nonce_2 =
				new BigInteger(1, responses.get("nonce_n2").getData());

		ProofU proofU = new ProofU(c, v_prime_response, s_response);
		return new IssueCommitmentMessage(U, proofU, nonce_2);
	}


    public static ProtocolCommands requestIssueSignatureCommands(CardVersion cv, IdemixCredentialDescription cd, IssueSignatureMessage signature_msg) {
        ProtocolCommands commands = new ProtocolCommands();
        IdemixSystemParameters sysPars = cd.getPublicKey().getSystemParameters();

        BigInteger A = signature_msg.getSignature().getA();
        commands.add(
                new ProtocolCommand(
                        "signature_A",
                        "Issue signature A",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_SIGNATURE, P1_SIGNATURE_A, 0x00,
                                fixLength(A, sysPars.l_n))));
        BigInteger e = signature_msg.getSignature().get_e();

        commands.add(
                new ProtocolCommand(
                        "signature_e",
                        "Issue signature e",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_SIGNATURE, P1_SIGNATURE_E, 0x00,
                                fixLength(e, sysPars.l_e))));

        BigInteger v = signature_msg.getSignature().get_v();
        commands.add(
                new ProtocolCommand(
                        "vPrimePrime",
                        "Issue signature v''",
                        new CommandAPDU(
                                CLA_IRMACARD, INS_ISSUE_SIGNATURE, P1_SIGNATURE_V, 0x00,
                                fixLength(v, sysPars.l_v))));

        BigInteger c = signature_msg.getProofS().get_c();
        BigInteger e_response = signature_msg.getProofS().get_e_response();
        if (cv.newer(new CardVersion(0,7,2))) {
	        commands.add(
	                new ProtocolCommand(
	                        "proof_c",
	                        "Issue proof c'",
	                        new CommandAPDU(
	                                CLA_IRMACARD, INS_ISSUE_SIGNATURE, P1_SIGNATURE_PROOF_C, 0x00,
	                                fixLength(c, sysPars.l_h))));

	        commands.add(
	                new ProtocolCommand(
	                        "proof_s_e",
	                        "Issue proof s_e",
	                        new CommandAPDU(
	                                CLA_IRMACARD, INS_ISSUE_SIGNATURE, P1_SIGNATURE_PROOF_S_E, 0x00,
	                                fixLength(e_response, sysPars.l_n))));
	        commands.add(
	                new ProtocolCommand(
	                        "issue_verify",
	                        "Verify issuance results (signature & proof)",
	                        new CommandAPDU(
	                                CLA_IRMACARD, INS_ISSUE_VERIFY, 0x00, 0x00)));
        } else {
	        commands.add(
	                new ProtocolCommand(
	                        "issue_verify",
	                        "Verify issuance results (signature & proof)",
	                        new CommandAPDU(
	                                CLA_IRMACARD, INS_ISSUE_SIGNATURE_0_7, P1_SIGNATURE_VERIFY_0_7, 0x00)));

	        commands.add(
	                new ProtocolCommand(
	                        "proof_c",
	                        "Issue proof c'",
	                        new CommandAPDU(
	                                CLA_IRMACARD, INS_ISSUE_SIGNATURE_PROOF_0_7, P1_PROOF_C_0_7, 0x00,
	                                fixLength(c, sysPars.l_h))));

	        commands.add(
	                new ProtocolCommand(
	                        "proof_s_e",
	                        "Issue proof s_e",
	                        new CommandAPDU(
	                                CLA_IRMACARD, INS_ISSUE_SIGNATURE_PROOF_0_7, P1_PROOF_S_E_0_7, 0x00,
	                                fixLength(e_response, sysPars.l_n))));
	        commands.add(
	                new ProtocolCommand(
	                        "issue_verify",
	                        "Verify issuance results (signature & proof)",
	                        new CommandAPDU(
	                                CLA_IRMACARD, INS_ISSUE_SIGNATURE_PROOF_0_7, P1_PROOF_VERIFY_0_7, 0x00)));
        }
        return commands;
    }



	public static ProtocolCommands buildProofCommands(CardVersion cv,
			final BigInteger nonce, IdemixVerificationDescription vd) {
		ProtocolCommands commands = new ProtocolCommands();

        IdemixPublicKey pk = vd.getIssuerPublicKey();
        IdemixSystemParameters sysPars = pk.getSystemParameters();

        commands.add(
                startProofCommand(cv, vd));
        commands.add(
                new ProtocolCommand(
                        "challenge_c",
                        "Send challenge n1",
                        new CommandAPDU(CLA_IRMACARD, INS_PROVE_COMMITMENT, 0x00, 0x00,
                                fixLength(nonce, sysPars.l_statzk))));
        commands.add(
                new ProtocolCommand(
                        "signature_A",
                        "Get random signature A",
                        new CommandAPDU(CLA_IRMACARD, INS_PROVE_SIGNATURE, P1_SIGNATURE_A, 0x00)));
        commands.add(
                new ProtocolCommand(
                        "signature_e",
                        "Get random signature e^",
                        new CommandAPDU(CLA_IRMACARD, INS_PROVE_SIGNATURE, P1_SIGNATURE_E, 0x00)));
        commands.add(
                new ProtocolCommand(
                        "signature_v",
                        "Get random signature v^",
                            new CommandAPDU(CLA_IRMACARD, INS_PROVE_SIGNATURE, P1_SIGNATURE_V, 0x00)));
        commands.add(
                new ProtocolCommand(
                        "master",
                        "Get random value (@index 0).",
                        new CommandAPDU(CLA_IRMACARD, INS_PROVE_ATTRIBUTE, 0x00, 0x00)));

        // Handle fixed attributes
        commands.add(
                new ProtocolCommand(
                        "attr_master",
                        "Get random value (@index 0).",
                        new CommandAPDU(CLA_IRMACARD, INS_PROVE_ATTRIBUTE, 0, 0x00)));

        // iterate over all the identifiers
        List<Integer> disclosed = vd.getDisclosedAttributeIdxs();
        for(int i = 0; i < vd.numberOfAttributes(); i++) {
			String attrName = vd.getAttributeName(i);
			boolean is_disclosed = disclosed.contains(i);
			commands.add(new ProtocolCommand(
						"attr_" + attrName,
						(is_disclosed ? "Get disclosed attribute"
							: "Get random value") + " (@index " + i + ").",
						new CommandAPDU(CLA_IRMACARD, INS_PROVE_ATTRIBUTE, i, 0x00)));
		}
        return commands;
    }

	public static IRMAIdemixDisclosureProof processBuildProofResponses(CardVersion cv,
			ProtocolResponses responses, final IdemixVerificationDescription vd) {
		BigInteger c = new BigInteger(1, responses.get("challenge_c").getData());
		BigInteger A = new BigInteger(1, responses.get("signature_A").getData());
		BigInteger e_response =
				new BigInteger(1, responses.get("signature_e").getData());
		BigInteger v_response =
				new BigInteger(1, responses.get("signature_v").getData());

		HashMap<Integer, BigInteger> a_responses = new HashMap<Integer, BigInteger>();
		HashMap<Integer, BigInteger> a_disclosed = new HashMap<Integer, BigInteger>();

        for(int i = 0; i < vd.numberOfAttributes(); i++ ) {
			String name = "attr_" + vd.getAttributeName(i);
			if (vd.isDisclosed(i)) {
				a_disclosed.put(i, new BigInteger(1, responses.get(name).getData()));
			} else {
				a_responses.put(i, new BigInteger(1, responses.get(name).getData()));
			}
        }

        // Return the generated proof, based on the proof specification
        return new IRMAIdemixDisclosureProof(c, A, e_response, v_response, a_responses, a_disclosed);
    }

    public static ProtocolCommand getCredentialsCommand(CardVersion cv) {
        return new ProtocolCommand(
            "getcredentials",
            "Get list of credentials",
            new CommandAPDU(CLA_IRMACARD, INS_ADMIN_CREDENTIALS, 0x00, 0x00));
    }

    public static ProtocolCommand selectCredentialCommand(CardVersion cv, short id) {
        if (cv.newer(new CardVersion(0,7,2))) {
            byte[] data = new byte[2];
            data[0] = (byte) (id >> 8);
            data[1] = (byte) (id & 0xff);

            return new ProtocolCommand(
                "selectcredential",
                "Select a credential for further modifications",
                new CommandAPDU(CLA_IRMACARD, INS_ADMIN_CREDENTIAL, 0, 0, data));
        } else {
            return new ProtocolCommand(
                "selectcredential",
                "Select a credential for further modifications",
                new CommandAPDU(CLA_IRMACARD, INS_ADMIN_CREDENTIAL, id >> 8, id & 0xff));
        }
    }

    public static ProtocolCommands requestGetAttributesCommands(CardVersion cv, IdemixCredentialDescription cd) {
        ProtocolCommands commands = new ProtocolCommands();
        commands.add(selectCredentialCommand(cv, cd.getCredentialDescription().getId()));
        for (int i = 1; i <= cd.numberOfAttributes(); i++) {
            String attrName = cd.getAttributeName(i);
            commands.add(new ProtocolCommand(
                "attr_" + attrName,
                "Get attribute (@index " + i + ")",
                new CommandAPDU(CLA_IRMACARD, INS_ADMIN_ATTRIBUTE, i, 0x00)));
        }
        return commands;
    }

    public static Attributes processGetAttributesCommands(CardVersion cv, IdemixCredentialDescription cd, ProtocolResponses responses) {
		Attributes attributes = new Attributes();
		for(int i = 1; i <= cd.numberOfAttributes(); i++) {
			String attrName = cd.getAttributeName(i);
			attributes.add(attrName,
					responses.get("attr_" + attrName).getData());
		}
		return attributes;
    }

    public static ProtocolCommand removeCredentialCommand(CardVersion cv, short id) {
        byte[] empty = {};
        if (cv.newer(new CardVersion(0,7,2))) {
            return new ProtocolCommand(
                    "removecredential",
                    "Remove credential (id " + id + ")",
                    new CommandAPDU(CLA_IRMACARD, INS_ADMIN_REMOVE, 0, 0, addTimeStamp(empty)));
        } else {
            return new ProtocolCommand(
                    "removecredential",
                    "Remove credential (id " + id + ")",
                    new CommandAPDU(CLA_IRMACARD, INS_ADMIN_REMOVE, id >> 8, id & 0xff, addTimeStamp(empty)));
        }
    }

    public static ProtocolCommand getCredentialFlagsCommand(CardVersion cv) {
        return new ProtocolCommand(
            "getcredflags",
            "Get credential flags",
            new CommandAPDU(CLA_IRMACARD, INS_ADMIN_FLAGS, 0, 0));
    }

    public static ProtocolCommand getLogCommand(CardVersion cv, byte idx) {
        return new ProtocolCommand(
            "getlog",
            "Get logs",
            new CommandAPDU(CLA_IRMACARD, INS_ADMIN_LOG, idx, 0));
    }

    public static ProtocolCommand setCredentialFlagsCommand(CardVersion cv, IdemixFlags flags) {
        return new ProtocolCommand(
            "setcredflags",
            "Set credential flags (" + flags + ")",
            new CommandAPDU(CLA_IRMACARD, INS_ADMIN_FLAGS, 0,0, flags.getFlagBytes()));
    }

    public static ProtocolCommands verifyCertificateCommands(CardVersion cv, Certificate cert) throws CertificateEncodingException {
        ProtocolCommands commands = new ProtocolCommands();
        if (!cv.older(new CardVersion(0,8))) {
            byte[] certBytes = cert.getEncoded();
            for (int offset = 0; offset < certBytes.length - 1; offset += 255) {
                commands.add(new ProtocolCommand(
                    "cert_" + offset,
                    "Verify certificate (@offset " + offset + ")",
                    new CommandAPDU(ISO7816.CLA_ISO7816 | ((offset + 255 < certBytes.length - 1) ? CLA_COMMAND_CHAINING : 0x00), ISO7816.INS_PSO, 0x00, 0xBE, Arrays.copyOfRange(certBytes, offset, Math.min(offset + 255, certBytes.length)))));
            }
        }

        return commands;
    }

    public static ProtocolCommands setCAKeyCommands(CardVersion cv, RSAPublicKey caKey) {
        ProtocolCommands commands = new ProtocolCommands();

        if (!cv.older(new CardVersion(0,8))) {
            commands.add(new ProtocolCommand(
                    "caExp",
                    "Set CA public key exponent",
                    new CommandAPDU(CLA_IRMACARD, INS_AUTHENTICATION_SECRET, 2, 0, fixLength(caKey.getPublicExponent(), 1024))));

            commands.add(new ProtocolCommand(
                    "caMod",
                    "Set CA public key modulus",
                    new CommandAPDU(CLA_IRMACARD, INS_AUTHENTICATION_SECRET, 3, 0, fixLength(caKey.getModulus(), 1024))));
        }

        return commands;
    }
}
