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
