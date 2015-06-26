/**
 * TestIRMACredential.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, September 2012.
 */


package org.irmacard.credentials.idemix;

import static org.junit.Assert.fail;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;

import javax.smartcardio.CardException;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.ProtocolCommands;
import net.sf.scuba.smartcards.ProtocolResponse;
import net.sf.scuba.smartcards.ProtocolResponses;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.categories.IssueTest;
import org.irmacard.credentials.idemix.categories.RemovalTest;
import org.irmacard.credentials.idemix.categories.VerificationTest;
import org.irmacard.credentials.idemix.descriptions.IdemixVerificationDescription;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.idemix.IdemixService;
import org.irmacard.idemix.IdemixSmartcard;
import org.irmacard.idemix.util.CardVersion;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;


public class TestIRMACredential {
	@BeforeClass
	public static void initializeInformation() throws InfoException {
		URI core = new File(System
				.getProperty("user.dir")).toURI()
				.resolve("irma_configuration/");
		DescriptionStore.setCoreLocation(core);
		DescriptionStore.getInstance();
		IdemixKeyStore.setCoreLocation(core);
		IdemixKeyStore.getInstance();
	}

	@Test
	public void generateMasterSecret() throws CardException, CardServiceException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		is.open();
		try {
		is.generateMasterSecret();
		} catch (CardServiceException e) {
			if (!e.getMessage().contains("6986")) {
				throw e;
			}
		}
	}

	@Test
	@Category(IssueTest.class)
	public void issueRootCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		issue("Surfnet", "root", getSurfnetAttributes());
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyRootCredentialAll() throws CardException,
			CredentialsException, InfoException {
		verify("Surfnet", "rootAll");
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyRootCredentialNone() throws CardException,
			CredentialsException, InfoException {
		verify("Surfnet", "rootNone");
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyRootCredentialAsync() throws CredentialsException, CardException, CardServiceException, InfoException {
		IdemixVerificationDescription vd =
				new IdemixVerificationDescription("Surfnet", "rootNone");
		IdemixCredentials ic = new IdemixCredentials(null);

		// Open channel to card
		IdemixService service = new IdemixService(TestSetup.getCardService());
		service.open();

		// Select applet and process version
		ProtocolResponse select_response = service.execute(
				IdemixSmartcard.selectApplicationCommand);
		CardVersion cv = new CardVersion(select_response.getData());

		// Generate a nonce (you need this for verification as well)
		BigInteger nonce = vd.generateNonce();

		// Get prove commands, and send them to card
		ProtocolCommands commands = ic.requestProofCommands(vd, nonce);
		ProtocolResponses responses = service.execute(commands);

		// Process the responses
		Attributes attr = ic.verifyProofResponses(vd, nonce, responses);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		service.close();
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyRootCredentialVoucher() throws CardException,
			CredentialsException, InfoException {
		verify("Surfnet", "studentVoucher");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeRootCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		remove("Surfnet", "root");
	}

	@Test
	@Category(IssueTest.class)
	public void issueStudentCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		issue("RU", "studentCard", getStudentCardAttributes());
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyStudentCredentialAll() throws CardException,
			CredentialsException, InfoException {
		verify("RU", "studentCardAll");
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyStudentCredentialNone() throws CardException, CredentialsException, InfoException {
		verify("RU", "studentCardNone");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeStudentCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		remove("RU", "studentCard");
	}

	@Test
	@Category(IssueTest.class)
	public void issueAgeCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		issue("MijnOverheid", "ageLower", getAgeAttributes());
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyAgeCredentialAll() throws CardException,
			CredentialsException, InfoException {
		verify("MijnOverheid", "ageLowerAll");
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyAgeCredentialNone() throws CardException,
			CredentialsException, InfoException {
		verify("MijnOverheid", "ageLowerNone");
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyAgeCredentialOver16() throws CardException, CredentialsException, InfoException {
		verify("UitzendingGemist", "ageLowerOver16");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeAgeCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		remove("MijnOverheid", "ageLower");
	}

	@Test
	@Category(IssueTest.class)
	public void issueAddressNijmegenCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		issue("MijnOverheid", "address", getAddressNijmegenAttributes());
	}

	@Test
	@Category(RemovalTest.class)
	public void removeAddressNijmegenCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		remove("MijnOverheid", "address");
	}

	@Test
	public void issueAddressReuverCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		issue("MijnOverheid", "address", getAddressReuverAttributes());
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyAddressCredentialAll() throws CardException,
			CredentialsException, InfoException {
		verify("MijnOverheid", "addressAll");
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyAddressCredentialNone() throws CardException, CredentialsException, InfoException {
		verify("MijnOverheid", "addressNone");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeAddressCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		remove("MijnOverheid", "address");
	}

	@Test
	@Category(IssueTest.class)
	public void issueMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		Attributes attributes = new Attributes();
		attributes.add("BSN", "123456789".getBytes());

		issue("MijnOverheid", "root", attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("MijnOverheid", "rootAll");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "root");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueFullNameCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		Attributes attributes = new Attributes();
		attributes.add("firstnames", "Johan Pieter".getBytes());
		attributes.add("firstname", "Johan".getBytes());
		attributes.add("familyname", "Stuivezand".getBytes());
		attributes.add("prefix", "van".getBytes());

		issue("MijnOverheid", "fullName", attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyFullNameCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("MijnOverheid", "fullNameAll");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeFullNameCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "fullName");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueBirthCertificate() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		Attributes attributes = new Attributes();
		attributes.add("dateofbirth", "29-2-2004".getBytes());
		attributes.add("placeofbirth", "Stuivezand".getBytes());
		attributes.add("countryofbirth", "Nederland".getBytes());
		attributes.add("gender", "male".getBytes());

		issue("MijnOverheid", "birthCertificate", attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyBirthCertificate() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("MijnOverheid", "birthCertificateAll");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeBirthCertificate() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "birthCertificate");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueSeniorAgeCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		Attributes attributes = new Attributes();
		attributes.add("over50", "yes".getBytes());
		attributes.add("over60", "no".getBytes());
		attributes.add("over65", "no".getBytes());
		attributes.add("over75", "no".getBytes());

		issue("MijnOverheid", "ageHigher", attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifySeniorAgeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("MijnOverheid", "ageHigherAll");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeSeniorAgeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "ageHigher");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueIRMATubeMemberCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		Attributes attributes = new Attributes();
		attributes.add("name", "J.P. Stuivezand".getBytes());
		attributes.add("type", "regular".getBytes());
		attributes.add("id", "123456".getBytes());

		issue("IRMATube", "member", attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMATubeMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("IRMATube", "memberAll");
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMATubeMemberTypeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("IRMATube", "memberType");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeIRMATubeMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("IRMATube", "member");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueIRMAWikiMemberCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		Attributes attributes = new Attributes();
		attributes.add("type", "regular".getBytes());
		attributes.add("nickname", "Stuifje Kuifje".getBytes());
		attributes.add("realname", "Stuifje".getBytes());
		attributes.add("email", "stuifje@kuifje.nl".getBytes());

		issue("IRMAWiki", "member", attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMAWikiMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("IRMAWiki", "memberAll");
	}

	@Test
	@Category(RemovalTest.class)
	public void removeIRMAWikiMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("IRMAWiki", "member");
		remove(cd);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMAWikiSurfnetRootNone() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		verify("IRMAWiki", "surfnetRootNone");
	}

	private void issue(String issuer, String credential, Attributes attributes)
			throws InfoException, CardException, CredentialsException,
			CardServiceException {
		CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescriptionByName(issuer, credential);
		issue(cd, attributes);
	}

	private void issue(CredentialDescription cd, Attributes attributes)
			throws InfoException, CardException, CredentialsException, CardServiceException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		ic.issue(cd, IdemixKeyStore.getInstance().getSecretKey(cd), attributes, null);
		is.close();
	}

	private void verify(String verifier, String verification_spec)
			throws CardException, CredentialsException, InfoException {
		verify(new IdemixVerificationDescription(verifier, verification_spec));
	}

	private void verify(IdemixVerificationDescription vd) throws CardException,
			CredentialsException {
		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);

		Attributes attr = ic.verify(vd);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}

		attr.print();
		cs.close();
	}

	private void remove(String issuer, String credential) throws InfoException,
			CardException, CredentialsException, CardServiceException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName(issuer, credential);

		remove(cd);
	}

	private void remove(CredentialDescription cd) throws CardException, CredentialsException, CardServiceException, InfoException {
		IdemixService is = TestSetup.getIdemixService();
		IdemixCredentials ic = new IdemixCredentials(is);

		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		try {
			ic.removeCredential(cd);
		} catch (CardServiceException e) {
			if (!e.getMessage().toUpperCase().contains("6A88")) {
				throw e;
			}
		}
		is.close();
	}

    private Attributes getStudentCardAttributes() {
        // Return the attributes that have been revealed during the proof
        Attributes attributes = new Attributes();

        System.out.println("Data: " + "Radboud University".getBytes().toString() + " Length: " + "Radboud University".getBytes().length);

		attributes.add("university", "Radboud University".getBytes());
		attributes.add("studentCardNumber", "0812345673".getBytes());
		attributes.add("studentID", "s1234567".getBytes());
		attributes.add("level", "Student".getBytes());

		return attributes;
	}

    private Attributes getSurfnetAttributes() {
        // Return the attributes that have been revealed during the proof
        Attributes attributes = new Attributes();

		attributes.add("userID", "s1234567@student.ru.nl".getBytes());
		attributes.add("securityHash", "DEADBEEF".getBytes());

		return attributes;
	}

    private Attributes getAgeAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("over12", "yes".getBytes());
		attributes.add("over16", "yes".getBytes());
		attributes.add("over18", "yes".getBytes());
		attributes.add("over21", "yes".getBytes());

		return attributes;
    }

    private Attributes getAddressNijmegenAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("country", "Nederland".getBytes());
		attributes.add("city", "Nijmegen".getBytes());
		attributes.add("street", "Heyendaalseweg 135".getBytes());
		attributes.add("zipcode", "6525 AJ".getBytes());

		return attributes;
    }

    private Attributes getAddressReuverAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("country", "Nederland".getBytes());
		attributes.add("city", "Reuver".getBytes());
		attributes.add("street", "Snavelbies 19".getBytes());
		attributes.add("zipcode", "5953 MR".getBytes());

		return attributes;
    }

}
