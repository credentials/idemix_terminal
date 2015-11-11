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

package org.irmacard.idemix.util;

import java.nio.ByteBuffer;
import java.util.Date;

import net.sf.scuba.util.Hex;

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
		terminal = new byte[SIZE_TERMINAL];
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

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		switch(action) {
		case VERIFY:
			sb.append("VERIFICATION\n")
					.append("Disclosed: ")
					.append(Hex.shortToHexString(disclose))
					.append("\n");
			break;
		case ISSUE:
			sb.append("ISSUANCE\n");
			break;
		case REMOVE:
			sb.append("REMOVE\n");
			break;
		case NONE:
			return "-- EMPTY ENTRY --";
		}

		sb.append("Timestamp: ")
				.append(getTimestamp().getTime())
				.append("\n")
				.append("Credential: ")
				.append(credential);

		return sb.toString();
	}

	public void print() {
		System.out.println(this.toString());
	}
}
