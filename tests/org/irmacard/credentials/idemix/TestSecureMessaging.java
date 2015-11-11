/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.credentials.idemix;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.util.Hex;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.info.InfoException;
import org.junit.BeforeClass;
import org.junit.Test;


public class TestSecureMessaging {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

	private static final IvParameterSpec ZERO_IV_PARAM_SPEC =
			new IvParameterSpec(new byte[8]);

	@BeforeClass
	public static void initializeInformation() {
		// TODO setup regular providers
		java.security.Security.addProvider(new com.sun.crypto.provider.SunJCE());
	}

	SecretKey getKey () {
		byte[] key = new byte[16];//{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
		SecretKey ksMac = new SecretKeySpec(key, "DESEDE");
		return ksMac;
	}

	@Test
	public void testMac() throws InvalidKeyException, NoSuchAlgorithmException {
		Mac mac = Mac.getInstance("DESEDEMAC64WITHISO7816-4PADDING");
		SecretKey ksMac = getKey();
		mac.init(ksMac);
		byte[] in = new byte[]{ 0x02 };
		byte[] out = mac.doFinal(in);
		System.out.println(Hex.toHexString(out));
	}

	@Test
	public void testEnc() throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
		SecretKey ksEnc = getKey();
		byte[] in = new byte[]{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
		cipher.init(Cipher.ENCRYPT_MODE, ksEnc, ZERO_IV_PARAM_SPEC);
		byte[] out2 = cipher.doFinal(in);
		System.out.println(Hex.toHexString(out2));
	}

	@Test
	public void verifyRootWithWrapping() throws CardException,
			CredentialsException, GeneralSecurityException, CardServiceException, InfoException {
		System.out.println("Running wrapping test");
		/*
		 * TODO: temporarily disabled
		VerifyCredentialInformation vci = new VerifyCredentialInformation("Surfnet", "rootAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		CardService terminal = TestSetup.getCardService();
		CardHolderVerificationService pinpad = new CardHolderVerificationService(terminal);
		SecureMessagingWrapper sm = new SecureMessagingWrapper(getKey() , getKey() );
		WrappingCardService wrapper = new WrappingCardService(pinpad, sm);
		IdemixService idemix = new IdemixService(wrapper);
		IdemixCredentials ic = new IdemixCredentials(wrapper);
		idemix.open();

		// Select Applet
		idemix.selectApplication();

		// Enable Secure Messaging
		wrapper.enable();

		// FIXME: We are using async here as well, since we need control over
		// the open command. This should actually be fixed in the API.

		Nonce nonce = ic.generateNonce(vspec);
		ProtocolCommands commands = ic.requestProofCommands(vspec, nonce);
		ProtocolResponses responses = idemix.execute(commands);
		Attributes attr = ic.verifyProofResponses(vspec, nonce, responses);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}

		attr.print();
		*/
	}

	@Test
	public void verifyRootAsyncWrapping() throws CardException,
			CredentialsException, GeneralSecurityException, CardServiceException, InfoException {
		/*
		 * TODO: Temporarily disabled
		VerifyCredentialInformation vci = new VerifyCredentialInformation("Surfnet", "rootAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		CardService terminal = TestSetup.getCardService();
		CardHolderVerificationService pinpad = new CardHolderVerificationService(terminal);
		SecureMessagingWrapper sm = new SecureMessagingWrapper(getKey() , getKey() );

		IdemixCredentials ic = new IdemixCredentials(pinpad);
		pinpad.open();

		// Select Applet
		IdemixService idemix = new IdemixService(pinpad);
		idemix.selectApplication();
		System.out.println("Applet selected");

		Nonce nonce = ic.generateNonce(vspec);
		ProtocolCommands commands = ic.requestProofCommands(vspec, nonce);

		// Store send sequence counter
		long ssc = sm.getSendSequenceCounter();

		//Wrap the commands
		sm.wrapAsync(commands);

		ProtocolResponses responses = idemix.execute(commands);

		// Unwrap the commands, here we need the send sequence counter
		sm.unWrapAsync(commands, responses, ssc + 1);

		Attributes attr = ic.verifyProofResponses(vspec, nonce, responses);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}

		attr.print();
		*/
	}
}
