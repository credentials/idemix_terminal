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
