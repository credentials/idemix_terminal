package org.irmacard.credentials.idemix.smartcard;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.Vector;
import java.util.logging.Logger;

import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.ISO7816;
import net.sourceforge.scuba.smartcards.ResponseAPDU;
import net.sourceforge.scuba.util.Hex;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.CredentialBuilder;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofU;
import org.irmacard.credentials.idemix.smartcard.PinCode.PinCodeStatus;
import org.irmacard.idemix.IdemixSmartcard;
import org.irmacard.idemix.util.IssuanceSetupData;
import org.irmacard.idemix.util.VerificationSetupData;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class IRMACard {
	protected final static byte CLA_SECURE_MESSAGING = (byte) 0x0C;
	protected final static byte CLA_COMMAND_CHAINING = (byte) 0x10;

	enum State {
		IDLE, APPLET_SELECTED, ISSUE, PROVE
	};

	enum IssueState {
		SETUP, PUBLIC_KEY, ATTRIBUTES, COMMITTED, CHALLENGED, SIGNATURE,
		VERIFY, FINISHED
	};

	enum VerificationState {
		SETUP, COMMITTED, SIGNATURE, ATTRIBUTES
	}

	protected final static byte[] fci = new byte[] { 0x6F, 0x16, (byte) 0xA5, 0x14,
			0x10, 0x12, 0x02, 0x01, 0x00, 0x02, 0x01, 0x08, 0x10, 0x0A, 0x0C,
			0x05, 0x61, 0x6C, 0x70, 0x68, 0x61, 0x02, 0x01, 0x00 };

	private final static Logger Log = Logger
			.getLogger(IRMACard.class.getName());
	private final static IdemixSystemParameters params = new IdemixSystemParameters();

	// Persistent state
	private PinCode credential_pin;
	private PinCode card_pin;
	private BigInteger master_secret;

	HashMap<Short, IdemixCredential> credentials;

	// Ephemeral state
	private State state;

	// Issuance state
	private IssueState issue_state;
	private IssuanceSetupData issuanceSetup;
	private CredentialBuilder cred_builder;
	private IdemixPublicKey issuer_pk;
	private List<BigInteger> attributes;
	private IssueCommitmentMessage commitment_message;
	private IssueSignatureMessage signature_message;

	// Verification state
	private VerificationState verification_state;
	private VerificationSetupData verificationSetup;
	private IdemixCredential credential;
	private ProofD proof;

	public IRMACard() {
		credential_pin = new PinCode(PinCode.DEFAULT_CRED_PIN);
		card_pin = new PinCode(PinCode.DEFAULT_CARD_PIN);
		master_secret = null;
		credentials = new HashMap<Short, IdemixCredential>();
		state = State.IDLE;
	}

	protected ResponseAPDU processAPDU(CommandAPDU apdu) {
		// FIXME ignoring secure channel for now

		switch ((byte) (apdu.getCLA()
				& (0xff ^ (CLA_COMMAND_CHAINING | CLA_SECURE_MESSAGING)))) {
		case ISO7816.CLA_ISO7816:
			switch ((byte) apdu.getINS()) {
			case ISO7816.INS_SELECT:
				return processSelectApplet(apdu);
			// Not yet implemented:
			//  * INS_PERFORM_SECURITY_OPERATION
			//  * INS_GET_CHALLENGE
			//  * INS_INTERNAL_AUTHENTICATE
			case ISO7816.INS_READ_BINARY_STAMPED:	// INS_PERFORM_SECURITY_OPERATION
			case ISO7816.INS_PSO: 					// INS_PERFORM_SECURITY_OPERATION
			case ISO7816.INS_INTERNAL_AUTHENTICATE:
				return sw(ISO7816.SW_FUNC_NOT_SUPPORTED);
			case ISO7816.INS_VERIFY:
				return processPINVerify(apdu);
			case ISO7816.INS_CHANGE_CHV:
				return processPINChange(apdu);
			default:
				Log.warning("Unknown instruction");
				System.out.println(Hex.bytesToHexString(apdu.getBytes()));
				return sw(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		case IdemixSmartcard.CLA_IRMACARD:
			switch(((byte) apdu.getINS()) & ((byte) 0xf0) ) {
			case 0x0:
				return processInitializationCommand(apdu);
			case 0x10:
				return processIssuanceCommand(apdu);
			case 0x20:
				return processVerificationCommand(apdu);
			case 0x30:
				return processAdministrationCommand(apdu);
			default:
				Log.warning("Unknown instruction");
				System.out.println(Hex.bytesToHexString(apdu.getBytes()));
				return sw(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		default:
			Log.warning("Unknown class");
			return sw(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}

	protected ResponseAPDU processSelectApplet(CommandAPDU apdu) {
		Log.info("Handling selectApplet");

		if( ((byte) apdu.getP1()) == IdemixSmartcard.P1_SELECT_BY_NAME &&
			    ((byte) apdu.getP2()) == 0x0) {
			if (Arrays.equals(apdu.getData(), IdemixSmartcard.AID)) {
				Log.info("IRMA applet selected");
				state = State.APPLET_SELECTED;
				return data_sw(fci, ISO7816.SW_NO_ERROR);
			}
		}
		// TODO maybe handle else case of outer if differently.

		Log.warning("Unknown applet selected: "
					+ Hex.bytesToHexString(apdu.getData()));
		return sw(ISO7816.SW_APPLET_SELECT_FAILED);
	}

	protected ResponseAPDU processPINVerify(CommandAPDU apdu) {
		Log.info("Handling processPinVerify");

		if (apdu.getP1() != 0x00) {
			return sw(ISO7816.SW_INCORRECT_P1P2);
		}

		PinCodeStatus result;
		int tries_left = 0;
		byte[] attempt = apdu.getData();

		switch (apdu.getP2()) {
		case(IdemixSmartcard.P2_PIN_ADMIN):
			Log.info("Verifying card administration PIN...");
			result = card_pin.verify(attempt);
			tries_left = card_pin.getTriesLeft();
			break;
		case(IdemixSmartcard.P2_PIN_ATTRIBUTE):
			Log.info("Verifying credential protection PIN...");
			result = credential_pin.verify(attempt);
			tries_left = credential_pin.getTriesLeft();
			break;
		default:
			Log.info("Unknown parameter for pin change...");
			return sw(ISO7816.SW_INCORRECT_P1P2);
		}

		switch (result) {
		case CORRECT:
			return sw(ISO7816.SW_NO_ERROR);
		case WRONG_LENGTH:
			return sw(ISO7816.SW_WRONG_LENGTH);
		default:
			return sw_counter(tries_left);
		}
	}

	protected ResponseAPDU processPINChange(CommandAPDU apdu) {
		// TODO implement
		Log.warning("Process PIN change not yet implemented");
		return sw(ISO7816.SW_FUNC_NOT_SUPPORTED);
	}

	protected ResponseAPDU processInitializationCommand(CommandAPDU apdu) {
		switch((byte) apdu.getINS()) {
		case IdemixSmartcard.INS_GENERATE_SECRET:
			return processGenerateSecret(apdu);
		default:
			Log.warning("Initialization command not yet implemented");
		}
		return sw(ISO7816.SW_FUNC_NOT_SUPPORTED);
	}

	protected ResponseAPDU processGenerateSecret(CommandAPDU apdu) {
		if (master_secret == null) {
			initializeMasterSecret();
			Log.info("Initialized master secret");
			return sw(ISO7816.SW_NO_ERROR);
		} else {
			Log.warning("Cannot generate master secret again");
			return sw(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
	}

	private void initializeMasterSecret() {
		Random rnd = new Random();
		master_secret = new BigInteger(new IdemixSystemParameters().l_m, rnd);
	}

	protected ResponseAPDU processIssuanceCommand(CommandAPDU apdu) {
		// You should enter pin before issueing
		if(!credential_pin.verified()) {
			Log.warning("Issuance started without entering PIN");
			return sw(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		if(master_secret == null) {
			initializeMasterSecret();
		}

		// Special case: start issuance
		if (apdu.getINS() == IdemixSmartcard.INS_ISSUE_CREDENTIAL) {
			return startIssuance(apdu);
		}

		// All other issuance cases
		if(state != State.ISSUE) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		switch((byte) apdu.getINS()) {
		case IdemixSmartcard.INS_ISSUE_PUBLIC_KEY:
			return processIssuePublicKey(apdu);
		case IdemixSmartcard.INS_ISSUE_ATTRIBUTES:
			return processIssueAttributes(apdu);
		case IdemixSmartcard.INS_ISSUE_COMMITMENT:
			return processIssueCommitment(apdu);
		case IdemixSmartcard.INS_ISSUE_COMMITMENT_PROOF:
			return processIssueCommitmentProof(apdu);
		case IdemixSmartcard.INS_ISSUE_CHALLENGE:
			return processIssueChallenge(apdu);
		case IdemixSmartcard.INS_ISSUE_SIGNATURE:
			return processIssueSignature(apdu);
		case IdemixSmartcard.INS_ISSUE_VERIFY:
			return processIssueVerify(apdu);
		}

		return sw(ISO7816.SW_FUNC_NOT_SUPPORTED);
	}

	private ResponseAPDU startIssuance(CommandAPDU apdu) {
		if(apdu.getP1() != 0 || apdu.getP2() != 0) {
			return sw(ISO7816.SW_WRONG_P1P2);
		}

		if(apdu.getData().length != IssuanceSetupData.SIZE) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}
		issuanceSetup = new IssuanceSetupData(apdu.getData());

		// TODO: check policy

		if(credentials.containsKey(issuanceSetup.getID())) {
			Log.info("Credential already exists, overwriting");
			// TODO check if overwrite is allowed.
		}

		// Prepare temporary storage of credential
		issuer_pk = new IdemixPublicKey(issuanceSetup.getSize() + 1);

		attributes = new Vector<BigInteger>(issuanceSetup.getSize());
		for(int i = 0; i < issuanceSetup.getSize(); i++) {
			attributes.add(null);
		}

		signature_message = new IssueSignatureMessage();

		// TODO create log entry

		state = State.ISSUE;
		issue_state = IssueState.SETUP;

		return sw(ISO7816.SW_NO_ERROR);
	}

	private ResponseAPDU processIssuePublicKey(CommandAPDU apdu) {
		Log.info("Processing public key");
		if(issue_state == IssueState.SETUP) {
			issue_state = IssueState.PUBLIC_KEY;
		}

		if(issue_state != IssueState.PUBLIC_KEY) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		if(apdu.getData().length != params.size_n) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		switch((byte) apdu.getP1()) {
		case IdemixSmartcard.P1_PUBLIC_KEY_N:
			Log.info("P1_PUBLIC_KEY_N");
			issuer_pk.set_n(new BigInteger(1, apdu.getData()));
			break;
		case IdemixSmartcard.P1_PUBLIC_KEY_Z:
			Log.info("P1_PUBLIC_KEY_Z");
			issuer_pk.set_Z(new BigInteger(1, apdu.getData()));
			break;
		case IdemixSmartcard.P1_PUBLIC_KEY_S:
			Log.info("P1_PUBLIC_KEY_S");
			issuer_pk.set_S(new BigInteger(1, apdu.getData()));
			break;
		case IdemixSmartcard.P1_PUBLIC_KEY_R:
			int idx = apdu.getP2();
			Log.info("P1_PUBLIC_KEY_R index: " + idx);

			if(idx > issuanceSetup.getSize() + 1) {
				Log.warning("Setting public key Ri out of range");
				return sw(ISO7816.SW_WRONG_P1P2);
			}

			issuer_pk.set_Ri(idx, new BigInteger(1, apdu.getData()));
			break;
		default:
			Log.warning("Unknown parameter");
			return sw(ISO7816.SW_WRONG_P1P2);
		}

		return sw(ISO7816.SW_NO_ERROR);
	}

	private ResponseAPDU processIssueAttributes(CommandAPDU apdu) {
		Log.info("Processing attributes");
		if(issue_state == IssueState.PUBLIC_KEY) {
			issue_state = IssueState.ATTRIBUTES;
		}

		// TODO additionally test that public key is complete
		if(issue_state != IssueState.ATTRIBUTES) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		if(apdu.getData().length != params.size_m) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		int idx = apdu.getP1();
		if(idx > issuanceSetup.getSize()) {
			Log.warning("Setting attribute out of range");
			return sw(ISO7816.SW_WRONG_P1P2);
		}

		BigInteger attr = new BigInteger(1, apdu.getData());
		if(attr.compareTo(BigInteger.ZERO) == 0) {
			Log.warning("Attribute cannot be zero");
			return sw(ISO7816.SW_WRONG_DATA);
		}

		attributes.set(idx - 1, attr);
		return sw(ISO7816.SW_NO_ERROR);
	}

	private ResponseAPDU processIssueCommitment(CommandAPDU apdu) {
		Log.info("Generating commitment");

		if(issue_state == IssueState.ATTRIBUTES) {
			issue_state = IssueState.COMMITTED;
		}

		// TODO additionally test that the attributes are complete
		if(issue_state != IssueState.COMMITTED) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		if(apdu.getData().length != params.size_statzk) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		BigInteger nonce1 = new BigInteger(1, apdu.getData());
		cred_builder = new CredentialBuilder(issuer_pk, attributes,
				issuanceSetup.getContext());
		commitment_message = cred_builder
				.commitToSecretAndProve(master_secret, nonce1);
		return data_sw(IdemixSmartcard.fixLength(
				commitment_message.getCommitment(), params.l_n),
				ISO7816.SW_NO_ERROR);
	}

	private ResponseAPDU processIssueCommitmentProof(CommandAPDU apdu) {
		Log.info("Sending commitment");

		if(issue_state != IssueState.COMMITTED) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		if(apdu.getData().length != 0) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		ProofU proof = commitment_message.getCommitmentProof();
		switch((byte) apdu.getP1()) {
		case IdemixSmartcard.P1_PROOF_C:
			Log.info("Sending challenge");
			return data(IdemixSmartcard.fixLength(proof.get_c(), params.l_h));
		case IdemixSmartcard.P1_PROOF_SHAT:
			Log.info("Sending s_response");
			return data(IdemixSmartcard.fixLength(proof.get_s_response(), 8*params.size_s_response));
		case IdemixSmartcard.P1_PROOF_VPRIMEHAT:
			Log.info("Sending v_prime_response");
			return data(IdemixSmartcard.fixLength(proof.get_v_prime_response(), 8*params.size_v_response));
		default:
			Log.warning("Unknown parameter");
			return sw(ISO7816.SW_WRONG_P1P2);
		}
	}

	private ResponseAPDU processIssueChallenge(CommandAPDU apdu) {
		if(issue_state == IssueState.COMMITTED) {
			issue_state = IssueState.CHALLENGED;
		}

		if(issue_state != IssueState.CHALLENGED) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		if(apdu.getData().length != 0) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		return data(IdemixSmartcard.fixLength(commitment_message.getNonce2(), 8*params.size_statzk));
	}

	private ResponseAPDU processIssueSignature(CommandAPDU apdu) {
		if(issue_state == IssueState.CHALLENGED) {
			issue_state = IssueState.SIGNATURE;
		}

		if(issue_state != IssueState.SIGNATURE) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		switch ((byte) apdu.getP1()) {
		case IdemixSmartcard.P1_SIGNATURE_A:
			Log.info("P1_SIGNATURE_A");

			if(apdu.getData().length != params.size_n) {
				return sw(ISO7816.SW_WRONG_LENGTH);
			}

			signature_message.getSignature().setA(
					new BigInteger(1, apdu.getData()));
			break;
		case IdemixSmartcard.P1_SIGNATURE_E:
			Log.info("P1_SIGNATURE_E");

			if(apdu.getData().length != params.size_e) {
				return sw(ISO7816.SW_WRONG_LENGTH);
			}

			signature_message.getSignature().set_e(
					new BigInteger(1, apdu.getData()));
			break;
		case IdemixSmartcard.P1_SIGNATURE_V:
			Log.info("P1_SIGNATURE_V");

			if(apdu.getData().length != params.size_v) {
				return sw(ISO7816.SW_WRONG_LENGTH);
			}

			signature_message.getSignature().set_v(
					new BigInteger(1, apdu.getData()));
			break;
		case IdemixSmartcard.P1_SIGNATURE_PROOF_C:
			Log.info("P1_SIGNATURE_PROOF_C");

			if(apdu.getData().length != params.size_h) {
				return sw(ISO7816.SW_WRONG_LENGTH);
			}

			signature_message.getProofS().set_c(
					new BigInteger(1, apdu.getData()));
			break;
		case IdemixSmartcard.P1_SIGNATURE_PROOF_S_E:
			Log.info("P1_SIGNATURE_PROOF_S_E");

			if(apdu.getData().length != params.size_n) {
				return sw(ISO7816.SW_WRONG_LENGTH);
			}

			signature_message.getProofS().set_e_response(
					new BigInteger(1, apdu.getData()));
			break;
		default:
			Log.warning("Unknown parameter");
			return sw(ISO7816.SW_WRONG_P1P2);
		}

		return sw(ISO7816.SW_NO_ERROR);
	}

	private ResponseAPDU processIssueVerify(CommandAPDU apdu) {
		Log.info("Verifying proof and signature");
		if(issue_state == IssueState.SIGNATURE) {
			issue_state = IssueState.VERIFY;
		}

		if(issue_state != IssueState.VERIFY) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		try {
			credentials.put(issuanceSetup.getID(),
					cred_builder.constructCredential(signature_message));
		} catch (CredentialsException e) {
			Log.info("Incorrect: " + e.toString());
			return sw(ISO7816.SW_DATA_INVALID);
		}

		Log.warning("ALL SUCCESFUL");

		issue_state = IssueState.FINISHED;
		state = State.APPLET_SELECTED;
		clearIssuanceState();

		return sw(ISO7816.SW_NO_ERROR);
	}

	private void clearIssuanceState() {
		issuanceSetup = null;
		cred_builder = null;
		issuer_pk = null;
		attributes = null;
		commitment_message = null;
		signature_message = null;
	}

	protected ResponseAPDU processVerificationCommand(CommandAPDU apdu) {
		// Special case: start issuance
		if (apdu.getINS() == IdemixSmartcard.INS_PROVE_CREDENTIAL) {
			return startVerification(apdu);
		}

		// All other issuance cases
		if(state != State.PROVE || credential == null) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		switch((byte) apdu.getINS()) {
		case IdemixSmartcard.INS_PROVE_COMMITMENT:
			return processProveCommitment(apdu);
		case IdemixSmartcard.INS_PROVE_SIGNATURE:
			return processProveSignature(apdu);
		case IdemixSmartcard.INS_PROVE_ATTRIBUTE:
			return processProveAttribute(apdu);
		}

		return sw(ISO7816.SW_FUNC_NOT_SUPPORTED);
	}

	protected ResponseAPDU startVerification(CommandAPDU apdu) {
		if (apdu.getP1() != 0 || apdu.getP2() != 0) {
			return sw(ISO7816.SW_WRONG_P1P2);
		}

		if (apdu.getData().length != VerificationSetupData.SIZE) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		verificationSetup = new VerificationSetupData(apdu.getData());

		// TODO: verify policy & verify content of verificationSetup

		if (!credentials.containsKey(verificationSetup.getID())) {
			Log.warning("Credential with id " + verificationSetup.getID() + " not found.");
			return sw(ISO7816.SW_KEY_NOT_FOUND);
		}
		credential = credentials.get(verificationSetup.getID());

		// Verify selection validity
		if(!verifySelection()) {
			credential = null;
			return sw(ISO7816.SW_WRONG_DATA);
		}

		// TODO: check if pin required, and check it

		// TODO: add log entry

		state = State.PROVE;
		verification_state = VerificationState.SETUP;
		return sw(ISO7816.SW_NO_ERROR);
	}

	protected ResponseAPDU processProveCommitment(CommandAPDU apdu) {
		Log.info("Generating commitment");

		if(verification_state != VerificationState.SETUP) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		if(apdu.getData().length != params.size_statzk) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		BigInteger nonce1 = new BigInteger(1, apdu.getData());

		List<Integer> disclosed_attributes = new ArrayList<Integer>();
		int mask = verificationSetup.getDisclosureMask();
		for(int i = 0; i <= credential.getNrAttributes(); i++) {
			if((mask & 0x01) == 0x01) {
				disclosed_attributes.add(i);
			}
			mask = mask >> 1;
		}
		proof = credential.createDisclosureProof(disclosed_attributes,
				verificationSetup.getContext(), nonce1);

		if(verification_state == VerificationState.SETUP) {
			verification_state = VerificationState.COMMITTED;
		}

		return data_sw(IdemixSmartcard.fixLength(
				proof.get_c(), params.l_h),
				ISO7816.SW_NO_ERROR);
	}

	protected ResponseAPDU processProveSignature(CommandAPDU apdu) {
		if(verification_state == VerificationState.COMMITTED) {
			verification_state = VerificationState.SIGNATURE;
		}

		if(verification_state != VerificationState.SIGNATURE) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		switch ((byte) apdu.getP1()) {
		case IdemixSmartcard.P1_SIGNATURE_A:
			Log.info("P1_SIGNATURE_A");
			return data(IdemixSmartcard.fixLength(proof.getA(), params.l_n));
		case IdemixSmartcard.P1_SIGNATURE_E:
			Log.info("P1_SIGNATURE_E");
			return data(IdemixSmartcard.fixLength(proof.get_e_response(),
					8 * params.size_e_response));
		case IdemixSmartcard.P1_SIGNATURE_V:
			Log.info("P1_SIGNATURE_V");
			return data(IdemixSmartcard.fixLength(proof.get_v_response(),
					8 * params.size_v_response));
		default:
			Log.warning("Unknown parameter");
			return sw(ISO7816.SW_WRONG_P1P2);
		}
	}

	protected ResponseAPDU processProveAttribute(CommandAPDU apdu) {
		if(verification_state == VerificationState.SIGNATURE) {
			verification_state = VerificationState.ATTRIBUTES;
		}

		if(verification_state != VerificationState.ATTRIBUTES) {
			return sw(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		if(apdu.getData().length != 0) {
			return sw(ISO7816.SW_WRONG_LENGTH);
		}

		if(apdu.getP1() > credential.getNrAttributes()) {
			return sw(ISO7816.SW_WRONG_P1P2);
		}

		int idx = apdu.getP1();
		if(verificationSetup.isDisclosed(idx)) {
			BigInteger attribute = proof.get_a_disclosed().get(idx);
			Log.info("Disclosing attribute " + idx + ": " + attribute);
			return data(IdemixSmartcard.fixLength(attribute, params.l_m));
		} else {
			BigInteger a_response = proof.get_a_responses().get(idx);
			Log.info("Sending response for attribute " + idx);
			return data(IdemixSmartcard.fixLength(a_response, 8*params.size_a_response));
		}
	}

	private boolean verifySelection() {
		short mask = verificationSetup.getDisclosureMask();
		if((mask & 0x01) != 0) {
			Log.warning("master secret cannot be disclosed");
			return false;
		}

		if((mask & 0x02) != 0x02) {
			Log.warning("metadata attribute must be disclosed");
			return false;
		}

		if((mask & (0xffff << (credential.getNrAttributes() + 1))) != 0) {
			Log.warning("Disclosing non-existing attribute");
			return false;
		}

		return true;
 	}

	protected ResponseAPDU processAdministrationCommand(CommandAPDU apdu) {
		return sw(ISO7816.SW_FUNC_NOT_SUPPORTED);
	}

	public void storeState(Path cardStoragePath) {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		Writer writer = null;
		try {
		    writer = new BufferedWriter(new OutputStreamWriter(
		          new FileOutputStream(cardStoragePath.toString()), "utf-8"));
		    writer.write(gson.toJson(this));
		} catch (IOException exception) {
			Log.warning("Couldn't write state to " + cardStoragePath);
			exception.printStackTrace();
		} finally {
		   try {writer.close();} catch (Exception ex) {}
		}
	}

	//
	// HELPER FUNCTIONS
	//

	protected ResponseAPDU sw_counter(int counter) {
		return sw((short) (0x63C0 + (counter & 0xf)));
	}

	protected ResponseAPDU data(byte[] data) {
		return data_sw(data, ISO7816.SW_NO_ERROR);
	}

	protected ResponseAPDU data_sw(byte[] data, short sw) {
		byte[] all = new byte[data.length + 2];
		byte[] status = asByteArray(sw);
		System.arraycopy(data, 0, all, 0, data.length);
		System.arraycopy(status, 0, all, data.length, 2);
		return new ResponseAPDU(all);
	}

	protected ResponseAPDU sw(short status) {
		return new ResponseAPDU(asByteArray(status));
	}

	protected byte[] asByteArray(short status) {
		byte msbyte = (byte) ((byte) (status >> 8) & ((byte) 0xff));
		byte lsbyte = (byte) (((byte) status) & ((byte) 0xff));

		return new byte[] {msbyte, lsbyte};
	}


}
