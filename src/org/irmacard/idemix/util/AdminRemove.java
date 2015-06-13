/**
 * AdminRemove.java
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
