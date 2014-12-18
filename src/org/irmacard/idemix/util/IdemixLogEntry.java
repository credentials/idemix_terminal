/**
 * IdemixLogEntry.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, March 2013.
 */

package org.irmacard.idemix.util;

import java.nio.ByteBuffer;
import java.util.Date;

import net.sourceforge.scuba.util.Hex;

/**
 * Low-level interface to the logs stored on the IRMA-card.
 *
 */
public class IdemixLogEntry {
	public enum Action {
		ISSUE,
		VERIFY,
		REMOVE,
		NONE
	}

	private int timestamp;
	private Action action;
	private short credential;
	private byte[] terminal;

	/** Only one of these is set simultaneously */
	private short disclose;
	private byte[] data;

	/**
	 * Structure of log entry:
	 *  timestamp: 4 bytes
	 *  terminal: 4 bytes
	 *  action: 1 byte
	 *  credential: 2 bytes (short)
	 *  details: 5 bytes
	 *     selection: 2 bytes (left aligned, short)
	 *     data: 5 bytes
	 */

	private static final int SIZE_TIMESTAMP = 4;
	private static final int SIZE_TERMINAL = 4;
	private static final int SIZE_ACTION = 1;
	private static final int SIZE_CREDID = 2;
	private static final int SIZE_DETAILS = 5;
	public static final int SIZE = SIZE_TIMESTAMP + SIZE_TERMINAL + SIZE_ACTION
			+ SIZE_CREDID + SIZE_DETAILS;

	private static final byte ACTION_NONE = 0x00;
	private static final byte ACTION_ISSUE = 0x01;
	private static final byte ACTION_PROVE = 0x02;
	private static final byte ACTION_REMOVE = 0x03;

	public IdemixLogEntry(byte[] log) {
		ByteBuffer buffer = ByteBuffer.wrap(log);
		data = null;
		disclose = 0;

		timestamp = buffer.getInt();

		terminal = new byte[SIZE_TERMINAL];
		buffer.get(terminal, 0, SIZE_TERMINAL);

		byte action_value = buffer.get();
		credential = buffer.getShort();

		switch (action_value) {
		case ACTION_ISSUE:
			action = Action.ISSUE;
			data = new byte[SIZE_DETAILS];
			buffer.get(data, 0, SIZE_DETAILS);
			break;
		case ACTION_PROVE:
			action = Action.VERIFY;
			disclose = buffer.getShort();
			break;
		case ACTION_REMOVE:
			action = Action.REMOVE;
			break;
		case ACTION_NONE:
			action = Action.NONE;
		}
	}

	public IdemixLogEntry(Action action, int timestamp, short credID, byte[] terminal) {
		this.action = action;
		this.timestamp = timestamp;
		this.credential = credID;
		this.terminal = terminal;
		this.data = new byte[SIZE_DETAILS];
	}

	public IdemixLogEntry() {
		action = Action.NONE;
		timestamp = 0;
		credential = 0;
		data = new byte[SIZE_DETAILS];
		disclose = 0;
	}

	public byte[] getBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);
		buffer.putInt(timestamp);
		buffer.put(terminal);

		switch(action) {
		case ISSUE:
			buffer.put(ACTION_ISSUE);
			break;
		case VERIFY:
			buffer.put(ACTION_PROVE);
			break;
		case REMOVE:
			buffer.put(ACTION_REMOVE);
			break;
		case NONE:
			buffer.put(ACTION_NONE);
			break;
		}

		buffer.putShort(credential);

		switch(action) {
		case ISSUE:
			buffer.put(data);
			break;
		case VERIFY:
			buffer.putShort(disclose);
			break;
		default:
			break;
		}

		return buffer.array();
	}

	public Date getTimestamp() {
		return new Date(((long) timestamp) * 1000);
	}

	public Action getAction() {
		return action;
	}

	public short getCredential() {
		return credential;
	}

	public byte[] getTerminal() {
		return terminal;
	}

	public short getDisclose() {
		return disclose;
	}

	public void setDisclose(short disclosureMask) {
		this.disclose = disclosureMask;
	}

	public byte[] getData() {
		return data;
	}

	public void print() {
		switch(action) {
		case VERIFY:
			System.out.println("VERIFICATION");
			System.out.println("Disclosed: " + Hex.shortToHexString(disclose));
			break;
		case ISSUE:
			System.out.println("ISSUANCE");
			break;
		case REMOVE:
			System.out.println("REMOVE");
			break;
		case NONE:
			System.out.println("-- EMPTY ENTRY --");
			return;
		}
		System.out.println("Timestamp: " + getTimestamp().getTime());
		System.out.println("Credential: " + credential);
	}
}
