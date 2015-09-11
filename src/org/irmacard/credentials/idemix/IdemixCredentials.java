/**
 * IdemixCredentials.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012,
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, July 2012.
 */

package org.irmacard.credentials.idemix;

import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.BaseCredentials;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.descriptions.IdemixCredentialDescription;
import org.irmacard.credentials.idemix.descriptions.IdemixVerificationDescription;
import org.irmacard.credentials.idemix.irma.IRMAIdemixDisclosureProof;
import org.irmacard.credentials.idemix.irma.IRMAIdemixIssuer;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.info.AttributeDescription;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.VerificationDescription;
import org.irmacard.credentials.util.log.IssueLogEntry;
import org.irmacard.credentials.util.log.LogEntry;
import org.irmacard.credentials.util.log.RemoveLogEntry;
import org.irmacard.credentials.util.log.VerifyLogEntry;
import org.irmacard.idemix.IdemixService;
import org.irmacard.idemix.IdemixSmartcard;
import org.irmacard.idemix.util.CardVersion;
import org.irmacard.idemix.util.IdemixLogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.ProtocolCommands;
import net.sf.scuba.smartcards.ProtocolResponses;

/**
 * An Idemix specific implementation of the credentials interface.
 */
public class IdemixCredentials extends BaseCredentials {
	IdemixService service = null;

	private static final Logger logger = LoggerFactory.getLogger(IdemixCredentials.class);

	public IdemixCredentials(CardService cs) {
		super(cs);
		if (cs instanceof IdemixService) {
			service = (IdemixService) cs;
		} else {
			service = new IdemixService(cs);
		}
	}

	public void connect()
	throws CredentialsException {
		try {
			service.open();
		} catch (CardServiceException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Issue a credential to the user according to the provided specification
	 * containing the specified values.
	 *
	 * This method requires the Idemix application to be selected and the card
	 * holder to be verified (if this is required by the card).
	 *
	 * @param specification
	 *            of the issuer and the credential to be issued.
	 * @param values
	 *            to be stored in the credential.
	 * @param expires
	 *            at this date, or after 6 months if null.
	 * @throws CredentialsException
	 *             if the issuance process fails.
	 */
	public void issue(CredentialDescription cd, IdemixSecretKey sk,
			Attributes attributes, Date expiry) throws CredentialsException {
		attributes.setExpireDate(expiry);
		attributes.setCredentialID(cd.getId());
		CardVersion cv = service.getCardVersion();

		IdemixCredentialDescription icd = null;
		BigInteger nonce1 = null;
		try {
			icd = new IdemixCredentialDescription(cd);
			nonce1 = icd.generateNonce();
		} catch (InfoException e) {
			throw new CredentialsException(e);
		}

		// Initialize the issuer
		IRMAIdemixIssuer issuer = new IRMAIdemixIssuer(icd.getPublicKey(), sk, icd.getContext());

		try {
			IssueCommitmentMessage commit_msg =
						IdemixSmartcard.processIssueCommitmentCommands(cv,
						service.execute(
						IdemixSmartcard.requestIssueCommitmentCommands(cv,
								icd, attributes, nonce1)));
			IssueSignatureMessage signature_msg =
					issuer.issueSignature(commit_msg, icd, attributes, nonce1);
			service.execute(
					IdemixSmartcard.requestIssueSignatureCommands(cv, icd, signature_msg));
			// FIXME: Check responses to round 3
		} catch (CardServiceException e) {
			throw new CredentialsException("Issuing caused exception", e);
		}
	}

	public void verifyPrepare()
	throws CredentialsException {
		try {
			service = new IdemixService(cs);
			service.open();
		} catch (CardServiceException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Verify a number of attributes listed in the specification.
	 *
	 * TODO: maybe interface is better when just passing VerificationDescription?
	 * TODO: see also corresponding IdemixSmartcard methods
	 *
	 * @param desc The VerificationDescription of the credential to be verified
	 * @return the attributes disclosed during the verification process or null
	 *         if verification failed
	 * @throws CredentialsException
	 */
	public Attributes verify(IdemixVerificationDescription desc)
			throws CredentialsException {
		verifyPrepare();

		CardVersion cv = service.getCardVersion();
		BigInteger nonce = desc.generateNonce();

		// Run the protocol
		try {
			return verifyProofResponses(desc, nonce,
					service.execute(IdemixSmartcard.buildProofCommands(cv, nonce, desc)));
		} catch (CardServiceException e) {
			throw new CredentialsException("Verification encountered error", e);
		}
	}

	private Attributes verifyProofResponses(IdemixVerificationDescription vd,
			BigInteger nonce, ProtocolResponses responses)
			throws CredentialsException {

		IRMAIdemixDisclosureProof proof = IdemixSmartcard
				.processBuildProofResponses(service.getCardVersion(),
						responses, vd);

		return proof.verify(vd, nonce);
	}

	/**
	 * First part of issuance protocol. Not yet included in the interface as
	 * this is subject to change. Most notably
	 *  - How do we integrate the issuer in this, I would guess the only state
	 *    in fact the nonce, so we could handle that a bit cleaner. Carrying around
	 *    the issuer object may not be the best solution
	 *  - We need to deal with the selectApplet and sendPinCommands better.
	 *
	 *  TODO: seems this doesn't quite belong here
	 * @throws CredentialsException
	 */
	public ProtocolCommands requestIssueCommitmentCommands(
			IdemixCredentialDescription cd, Attributes attributes, BigInteger nonce1)
			throws CredentialsException {
		CardVersion cv = service.getCardVersion();
		return IdemixSmartcard.requestIssueCommitmentCommands(cv, cd, attributes, nonce1);
	}

	public BigInteger generateNonce(VerificationDescription cd) {
		// TODO: extract public key from credential description
		IdemixSystemParameters params = new IdemixSystemParameters();

		Random rnd = new Random();
		return new BigInteger(params.l_statzk, rnd);
	}

	/**
	 * Get the attribute values stored on the card for the given credential.
	 *
	 * @param credential identifier.
	 * @return attributes for the given credential.
	 * @throws CardServiceException
	 * @throws CredentialsException
	 */
	public Attributes getAttributes(CredentialDescription cd)
			throws CardServiceException, CredentialsException {
		IdemixCredentialDescription icd = null;
		try {
			icd = new IdemixCredentialDescription(cd);
		} catch (InfoException e) {
			throw new CredentialsException(e);
		}

		ProtocolResponses responses = service.execute(IdemixSmartcard
				.requestGetAttributesCommands(getCardVersion(), icd));
		return IdemixSmartcard.processGetAttributesCommands(getCardVersion(),
				icd, responses);
	}

	public void removeCredential(CredentialDescription cd) throws CardServiceException {
		service.selectCredential(cd.getId());
		service.removeCredential(cd.getId());
	}

	/**
	 * Get a list of credentials available on the card.
	 *
	 * @return list of credential identifiers.
	 * @throws CardServiceException
	 * @throws InfoException
	 */
	public List<CredentialDescription> getCredentials() throws CardServiceException, InfoException {
		Vector<Integer> credentialIDs = service.getCredentials();

		List<CredentialDescription> credentialList = new Vector<CredentialDescription>();;
		DescriptionStore ds = DescriptionStore.getInstance();

		for(Integer id : credentialIDs) {
			CredentialDescription cd = ds.getCredentialDescription(id.shortValue());
			if(cd != null) {
				credentialList.add(cd);
			} else {
				throw new InfoException("Description for credential with ID=" + id + " not found");
			}
		}

		return credentialList;
	}

	@Override
	public List<LogEntry> getLog() throws CardServiceException, InfoException {
		List<IdemixLogEntry> idemix_logs = service.getLogEntries();
		Vector<LogEntry> logs = new Vector<LogEntry>();
		LogEntry entry = null;

		for(IdemixLogEntry l : idemix_logs) {
			if(l.getAction() == IdemixLogEntry.Action.NONE)
				continue;

			DescriptionStore ds = DescriptionStore.getInstance();
			Date timestamp = l.getTimestamp();
			CredentialDescription credential = ds.getCredentialDescription(l.getCredential());
			if(credential == null) {
				logger.warn("This shouldn't happen, cannot find the description");
				logger.warn(l.toString());
				continue;
			}

			switch (l.getAction()) {
			case ISSUE:
				entry = new IssueLogEntry(timestamp, credential);
				break;
			case REMOVE:
				entry = new RemoveLogEntry(timestamp, credential);
				break;
			case VERIFY:
				entry = new VerifyLogEntry(timestamp,
						credential, null, makeAttributeDisclosed(credential,
								l.getDisclose()));
				break;

			// These should not happen...
			case NONE:
			default:
				continue;
			}
			logs.add(entry);
		}

		return logs;
	}

	private HashMap<String, Boolean> makeAttributeDisclosed(CredentialDescription cred, short disclose) {
		HashMap<String, Boolean> attributeDisclosed = new HashMap<String, Boolean>();
		List<AttributeDescription> attributes = cred.getAttributes();

		// Start at 2 so we skip the master secret and metadata
		for (int i = 2; i < attributes.size() + 2; i++) {
			attributeDisclosed.put(attributes.get(i-2).getName(), new Boolean(
					(disclose & (1 << i)) != 0));
		}

		return attributeDisclosed;
	}

	public CardVersion getCardVersion() {
		return service.getCardVersion();
	}
}
