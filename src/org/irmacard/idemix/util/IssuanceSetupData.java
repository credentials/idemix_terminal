/**
 * IssuanceSetupData.java
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


public class IssuanceSetupData {
	// TODO: reference IdemixSystemParameters after fixing dependencies
	public static final int SIZE_CONTEXT = 32;

	public static final int SIZE_CRED_ID = 2;
	public static final int SIZE_SIZE = 2;
	public static final int SIZE_TIMESTAMP = 4;
	public static final int SIZE = SIZE_CRED_ID + SIZE_SIZE + IdemixFlags.SIZE
			+ SIZE_CONTEXT + SIZE_TIMESTAMP;

	private short id;
	private short size;
	private IdemixFlags flags;
	private BigInteger context;
	private int timestamp;

	public IssuanceSetupData(short id, short size, IdemixFlags flags, BigInteger context, int timestamp) {
		this.id = id;
		this.size = size;
		this.flags = flags;
		this.context = context;
		this.timestamp = timestamp;
	}

	public IssuanceSetupData(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);

		id = buffer.getShort();
		size = buffer.getShort();

		byte[] raw_flags = new byte[IdemixFlags.SIZE];
		buffer.get(raw_flags);
		flags = new IdemixFlags(raw_flags);

		byte[] raw_context = new byte[SIZE_CONTEXT];
		buffer.get(raw_context);
		context = new BigInteger(1, raw_context);

		timestamp = buffer.getInt();
	}

	public byte[] getBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);

		return buffer.putShort(id).putShort(size)
				.put(flags.getFlagBytes())
				.put(IdemixSmartcard.fixLength(context, SIZE_CONTEXT * 8))
				.putInt(timestamp).array();
	}

	public short getID() {
		return id;
	}

	public short getSize() {
		return size;
	}

	public IdemixFlags getFlags() {
		return flags;
	}

	public BigInteger getContext() {
		return context;
	}

	public int getTimestamp() {
		return timestamp;
	}
}
