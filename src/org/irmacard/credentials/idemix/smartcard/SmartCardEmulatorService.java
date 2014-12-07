package org.irmacard.credentials.idemix.smartcard;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.ResponseAPDU;

import com.google.gson.Gson;

public class SmartCardEmulatorService extends CardService {
	private static final long serialVersionUID = 1L;
	boolean open = false;
	IRMACard card;
	Path cardStoragePath;

	public SmartCardEmulatorService() {
		card = new IRMACard();
	}

	public SmartCardEmulatorService(Path path) {
		this.cardStoragePath = path;

		Gson gson = new Gson();
		try {
			byte[] data = Files.readAllBytes(cardStoragePath);
			card = gson.fromJson(new String(data), IRMACard.class);
		} catch (IOException e) {
			e.printStackTrace();
			card = new IRMACard();
		}
	}

	@Override
	public void close() {
		if(cardStoragePath != null) {
			card.storeState(cardStoragePath);
		}
		open = false;
	}

	@Override
	public byte[] getATR() throws CardServiceException {
		return null;
	}

	@Override
	public String getName() {
		return "Idemix SmartCard Emulator";
	}

	@Override
	public boolean isOpen() {
		return open;
	}

	/**
	 * Open a connection to the card. Calling this function twice is allowed (for now).
	 */
	@Override
	public void open() throws CardServiceException {
		open = true;
	}

	@Override
	public ResponseAPDU transmit(CommandAPDU apdu) throws CardServiceException {
		return card.processAPDU(apdu);
	}

	@Override
	public byte[] transmitControlCommand(int arg0, byte[] arg1)
			throws CardServiceException {
		// TODO Auto-generated method stub
		return null;
	}
}
