/**
 * VerificationSetupData.java
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

package org.irmacard.idemix.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.irmacard.idemix.IdemixSmartcard;

public class VerificationSetupData {
	// TODO: reference IdemixSystemParameters after fixing dependencies
	public static final int SIZE_CONTEXT = 32;

	public static final int SIZE_CRED_ID = 2;
	public static final int SIZE_ATTRIBUTE_MASK = 2;
	public static final int SIZE_TIMESTAMP = 4;
	public static final int SIZE = SIZE_CRED_ID + SIZE_ATTRIBUTE_MASK
			+ SIZE_CONTEXT + SIZE_TIMESTAMP;

	private short cred_id;
	private short mask;
	private BigInteger context;
	private int timestamp;

	public VerificationSetupData(short cred_id, short mask, BigInteger context, int timestamp) {
		this.cred_id = cred_id;
		this.mask = mask;
		this.context = context;
		this.timestamp = timestamp;
	}

	public VerificationSetupData(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);

		cred_id = buffer.getShort();
		mask = buffer.getShort();

		byte[] raw_context = new byte[SIZE_CONTEXT];
		buffer.get(raw_context);
		context = new BigInteger(1, raw_context);

		timestamp = buffer.getInt();
	}

	public byte[] getBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);

		return buffer.putShort(cred_id).putShort(mask)
				.put(IdemixSmartcard.fixLength(context, SIZE_CONTEXT * 8))
				.putInt(timestamp).array();
	}

	public short getID() {
		return cred_id;
	}

	public short getDisclosureMask() {
		return mask;
	}

	public BigInteger getContext() {
		return context;
	}

	public int getTimestamp() {
		return timestamp;
	}

	public boolean isDisclosed(int idx) {
		return ((mask >> idx) & 0x01) != 0;
	}

	public String toString() {
		return "VerificationSetup: id=" + cred_id + " mask=" + mask
				+ " timestamp=" + timestamp + " context=" + context;
	}
}
