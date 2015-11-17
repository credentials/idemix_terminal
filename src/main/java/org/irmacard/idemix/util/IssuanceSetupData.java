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
