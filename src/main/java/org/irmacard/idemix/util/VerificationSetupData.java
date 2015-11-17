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

import org.irmacard.credentials.idemix.descriptions.IdemixVerificationDescription;
import org.irmacard.idemix.IdemixSmartcard;

public class VerificationSetupData {
	// TODO: reference IdemixSystemParameters after fixing dependencies
	// TODO: in fact, this depends on the specific parameter set
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

	public VerificationSetupData(IdemixVerificationDescription vd, int timestamp) {
		this.cred_id = vd.getVerificationDescription().getCredentialDescription().getId();
		this.mask = vd.getDisclosureMask();
		this.context = vd.getContext();
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

	public byte[] getBytes(CardVersion cv) {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);

		if (cv == null || cv.newer(new CardVersion(0, 7, 2))) {
			return buffer.putShort(cred_id).putShort(mask)
					.put(IdemixSmartcard.fixLength(context, SIZE_CONTEXT * 8))
					.putInt(timestamp).array();
		} else {
			return buffer.putShort(cred_id)
					.put(IdemixSmartcard.fixLength(context, SIZE_CONTEXT * 8))
					.putShort(mask).putInt(timestamp).array();
		}
	}

	public byte[] getBytes() {
		return getBytes(null);
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
