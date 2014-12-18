/**
 * IdemixFlags.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen.
 */

package org.irmacard.idemix.util;

public class IdemixFlags {

	private short pinProtectionMask;
	private byte RFU;

	public static final int SIZE = 3;

	public IdemixFlags(byte[] flags) {
		pinProtectionMask = getShortAt(flags, 0);
		RFU = flags[2];
	}

	public IdemixFlags() {
		pinProtectionMask = 0;
		RFU = 0;
	}

	public IdemixFlags(short pinProtectionMask) {
		this.pinProtectionMask = pinProtectionMask;
		RFU = 0;
	}

	public IdemixFlags(short pinProtectionMask, byte RFU) {
		this.pinProtectionMask = pinProtectionMask;
		this.RFU = RFU;
	}

	public byte[] getFlagBytes() {
		byte[] flags = new byte[3];
		flags = putShortAt(flags, 0, pinProtectionMask);
		flags[2] = RFU;
		return flags;
	}

	public short getPinProtectionMask() {
		return pinProtectionMask;
	}

	public byte getRFU() {
		return RFU;
	}

	private static short getShortAt(byte[] array, int idx) {
		return (short) (((array[idx] & 0xff) << 8) | (array[idx + 1] & 0xff));
	}

	private static byte[] putShortAt(byte[] array, int idx, int value) {
		array[idx] = (byte) (value >> 8);
		array[idx + 1] = (byte) (value & 0xff);
		return array;
	}
}
