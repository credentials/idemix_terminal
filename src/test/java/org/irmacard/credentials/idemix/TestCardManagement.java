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

import java.io.File;
import java.net.URI;
import java.util.List;

import javax.smartcardio.CardException;

import net.sf.scuba.smartcards.CardServiceException;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.util.log.LogEntry;
import org.irmacard.idemix.IdemixService;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestCardManagement {
	@BeforeClass
	public static void initializeInformation() {
		URI core = new File(System.getProperty("user.dir")).toURI().resolve(
				"irma_configuration/");
		DescriptionStore.setCoreLocation(core);
		IdemixKeyStore.setCoreLocation(core);
	}

	@Test
	public void testGetCredentials() throws CredentialsException, CardServiceException, InfoException, CardException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);

		List<CredentialDescription> credentials = ic.getCredentials();

		System.out.println("Found the following credentials on the card:");
		for(CredentialDescription ds : credentials) {
			System.out.println(" * " + ds.toString());
		}
	}

	/**
	 * For now we assume that at least one credential has been loaded on the card.
	 * @throws CredentialsException
	 * @throws CardServiceException
	 * @throws InfoException
	 * @throws CardException
	 */
	@Test
	public void testGetAttributes() throws CredentialsException, CardServiceException, InfoException, CardException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);

		List<CredentialDescription> credentials = ic.getCredentials();

		System.out.println("Found the following credentials on the card:");
		for(CredentialDescription ds : credentials) {
			System.out.println(" * " + ds.toString());
			Attributes attr = ic.getAttributes(ds);
			attr.print();
		}
	}

	@Test
	public void testGetLogs() throws CardException, CredentialsException, CardServiceException, InfoException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);

		List<LogEntry> logs = ic.getLog();
		for(LogEntry log_entry : logs) {
			System.out.println(log_entry.toString());
		}
	}
}
