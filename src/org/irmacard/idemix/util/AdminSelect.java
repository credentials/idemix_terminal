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

public class AdminSelect {
	private short id;

	public static final int SIZE = 2;

	public AdminSelect(short id) {
		this.id = id;
	}

	public AdminSelect(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);
		id = buffer.getShort();
	}

	public short getID() {
		return id;
	}
}
