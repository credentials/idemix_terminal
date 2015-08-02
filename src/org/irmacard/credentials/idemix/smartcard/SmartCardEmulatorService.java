/**
 * SmartCardEmulatorService.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, December 2014.
 */

package org.irmacard.credentials.idemix.smartcard;

import java.util.LinkedList;
import java.util.List;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;

public class SmartCardEmulatorService extends CardService {
	private static final long serialVersionUID = 1L;
	boolean open = false;
	IRMACard card;
	List<CardChangedListener> listeners;

	public SmartCardEmulatorService() {
		card = new IRMACard();
		listeners = new LinkedList<CardChangedListener>();
	}

	public SmartCardEmulatorService(IRMACard card) {
		this.card = card;
		listeners = new LinkedList<CardChangedListener>();
	}

	public void addListener(CardChangedListener listener) {
		listeners.add(listener);
	}

	public IRMACard getCard() {
		return card;
	}

	@Override
	public void close() {
		for(CardChangedListener listener : listeners) {
			listener.cardChanged(card);
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
		if (!open) {
			throw new CardServiceException("Card hasn't been opened");
		}
		return card.processAPDU(apdu);
	}

	@Override
	public byte[] transmitControlCommand(int arg0, byte[] arg1)
			throws CardServiceException {
		// TODO Auto-generated method stub
		return null;
	}
}
