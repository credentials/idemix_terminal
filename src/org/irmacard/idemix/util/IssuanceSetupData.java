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

/**
 * Represents the data that is sent to describe a new issuance. These data
 * describe the credential id, the size of the credential, a time stamp (the
 * card uses it to log the issuance) and the context of this issuance.
 */
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

	/**
	 * Construct an IssuanceSetupData object by pass its data fields
	 *
	 * @param id
	 *            the credential id
	 * @param size
	 *            the number of attributes of the credential (including
	 *            metadata)
	 * @param flags
	 *            the IdemixFlags (see @IdemixFlags)
	 * @param context
	 *            the context that is to be used for the proofs
	 * @param timestamp
	 *            the time stamp (in seconds since epoch)
	 */
	public IssuanceSetupData(short id, short size, IdemixFlags flags, BigInteger context, int timestamp) {
		this.id = id;
		this.size = size;
		this.flags = flags;
		this.context = context;
		this.timestamp = timestamp;
	}

	/**
	 * Construct an IssuanceSetupData object from its byte-encoding.
	 *
	 * @param data
	 *            a byte-encoding of the object
	 */
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

	/**
	 * Returns the default byte-encoding of the object.
	 *
	 * @return the byte-encoding of the object
	 */
	public byte[] getBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);

		return buffer.putShort(id).putShort(size)
				.put(flags.getFlagBytes())
				.put(IdemixSmartcard.fixLength(context, SIZE_CONTEXT * 8))
				.putInt(timestamp).array();
	}

	/**
	 * Returns the legacy byte-encoding of the object
	 *
	 * @return the legacy byte-encoding of the object
	 */
	public byte[] getBytesLegacy() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE_CRED_ID + SIZE_CONTEXT + SIZE_SIZE + SIZE_TIMESTAMP);

		return buffer.putShort(id)
				.put(IdemixSmartcard.fixLength(context, SIZE_CONTEXT * 8))
				.putShort(size)
				.putInt(timestamp).array();
	}

	/**
	 * Returns the byte-encoding of the object appropriate for the given
	 * CardVersion.
	 *
	 * @param cv
	 *            the card version
	 * @return the appropriate byte-encoding.
	 */
	public byte[] getBytes(CardVersion cv) {
		if (cv.newer(new CardVersion(0, 7, 2))) {
        	return getBytes();
		} else {
			return getBytesLegacy();
		}
	}

	/**
	 * Returns the credential id.
	 *
	 * @return the credential id
	 */
	public short getID() {
		return id;
	}

	/**
	 * Returns the number of attributes in the credential (including metadata,
	 * excluding the master secret).
	 *
	 * @return the number of attributes in the credential
	 */
	public short getSize() {
		return size;
	}

	/**
	 * Returns the idemix flag associated with this issuance, see @IdemixFlags.
	 *
	 * @return The idemix flags.
	 */
	public IdemixFlags getFlags() {
		return flags;
	}

	/**
	 * Returns the context associated with this issuance.
	 *
	 * @return The context
	 */
	public BigInteger getContext() {
		return context;
	}

	/**
	 * Returns the time stamp (in seconds since epoch) associated with this issuance.
	 *
	 * @return the timestamp (in seconds since epoch)
	 */
	public int getTimestamp() {
		return timestamp;
	}
}
