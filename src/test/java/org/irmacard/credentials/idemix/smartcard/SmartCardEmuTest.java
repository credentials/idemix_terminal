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

package org.irmacard.credentials.idemix.smartcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ProtocolCommand;
import net.sf.scuba.smartcards.ResponseAPDU;

import org.irmacard.idemix.IdemixSmartcard;
import org.junit.Test;

public class SmartCardEmuTest {
	@Test
	public void testResponseAPDUShort() {
		IRMACard card = new IRMACard();

		short input = (short) 47436;
		byte[] output = new byte[] {(byte) 0xb9, 0x4c};

		ResponseAPDU response = card.sw(input);
		assertArrayEquals(response.getBytes(), output);
	}

	@Test
	public void selectApplet() {
		IRMACard card = new IRMACard ();
		ProtocolCommand cmd = IdemixSmartcard.selectApplicationCommand;
		ResponseAPDU response = card.processAPDU(cmd.getAPDU());
		assertArrayEquals(IRMACard.fci, response.getData());
	}

	@Test
	public void testCredentialPIN() {
		IRMACard card = new IRMACard();
		ProtocolCommand cmd;
		ResponseAPDU response;

		// Correct PIN
		cmd = IdemixSmartcard.sendPinCommand(null, IdemixSmartcard.P2_PIN_ATTRIBUTE, PinCode.DEFAULT_CRED_PIN);
		response = card.processAPDU(cmd.getAPDU());
		System.out.println(response + ", " + (short) response.getSW() + ", " + ISO7816.SW_NO_ERROR);
		assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

		// Incorrect PIN
		cmd = IdemixSmartcard.sendPinCommand(null, IdemixSmartcard.P2_PIN_ATTRIBUTE, PinCode.DEFAULT_CARD_PIN);
		response = card.processAPDU(cmd.getAPDU());
		assertEquals((short) response.getSW(), (short) (0x63c0 + 2));

		// Incorrect PIN (again)
		cmd = IdemixSmartcard.sendPinCommand(null, IdemixSmartcard.P2_PIN_ATTRIBUTE, PinCode.DEFAULT_CARD_PIN);
		response = card.processAPDU(cmd.getAPDU());
		assertEquals((short) response.getSW(), (short) (0x63c0 + 1));

		// Incorrect PIN (twice more)
		cmd = IdemixSmartcard.sendPinCommand(null, IdemixSmartcard.P2_PIN_ATTRIBUTE, PinCode.DEFAULT_CARD_PIN);
		card.processAPDU(cmd.getAPDU());
		response = card.processAPDU(cmd.getAPDU());
		assertEquals((short) response.getSW(), (short) (0x63c0));

		System.out.println(response);
	}
}
