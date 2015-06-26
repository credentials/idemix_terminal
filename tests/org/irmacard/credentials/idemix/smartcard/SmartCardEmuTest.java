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
