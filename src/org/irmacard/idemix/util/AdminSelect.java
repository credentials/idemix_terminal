/**
 * AdminSelect.java
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
 * Represents the data that is sent along with a credential select command. This
 * data specifies the credential id.
 */
public class AdminSelect {
	private short id;

	public static final int SIZE = 2;

	/**
	 * Construct an AdminSelect object using a credential id.
	 * @param id		the credential id
	 */
	public AdminSelect(short id) {
		this.id = id;
	}

	/**
	 * Construct an AdminSelect object from its byte-encoding.
	 * @param data		a byte-encoding of the object
	 */
	public AdminSelect(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);
		id = buffer.getShort();
	}

	/**
	 * Returns the default byte-encoding of the object.
	 *
	 * @return the byte-encoding of the object
	 */
	public byte[] getBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);

		return buffer.putShort(id).array();
	}

	/**
	 * Returns the credential id.
	 *
	 * @return	the credential id
	 */
	public short getID() {
		return id;
	}
}
