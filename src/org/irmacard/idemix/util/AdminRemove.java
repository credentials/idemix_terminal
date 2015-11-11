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

/**
 * Represents the extra data that is sent along with a credential remove
 * command. These data contain a time stamp to update the card's current time
 * estimate. The card uses it to log the credential's removal.
 */
public class AdminRemove {
	private static final int SIZE_TIMESTAMP = 4;

	public static final int SIZE = SIZE_TIMESTAMP;

	private int timestamp;

	/**
	 * Construct an AdminRemove object using a time stamp.
	 * @param timestamp		the time stamp
	 */
	public AdminRemove(int timestamp) {
		this.timestamp = timestamp;
	}

	/**
	 * Construct an AdminRemove object from its byte-encoding.
	 * @param data			a byte-encoding of the object
	 */
	public AdminRemove(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);
		timestamp = buffer.getInt();
	}

	/**
	 * Returns the default byte-encoding of the object.
	 *
	 * @return the byte-encoding of the object
	 */
	public byte[] getBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);

		return buffer.putInt(timestamp).array();
	}

	/**
	 * Returns the time stamp encoded into this object.
	 *
	 * @return	the time stamp
	 */
	public int getTimeStamp() {
		return timestamp;
	}
}
