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

package org.irmacard.credentials.idemix.smartcard;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.Random;

import org.irmacard.idemix.util.IdemixFlags;
import org.irmacard.idemix.util.IssuanceSetupData;
import org.junit.Test;

public class DataPackagesTest {
	@Test
	public void packUnPackIdemixFlags() {
		short flags = (short) 0xda81;
		byte rfu = (byte) 0xc8;

		IdemixFlags orig = new IdemixFlags(flags, rfu);
		byte[] representation = orig.getFlagBytes();
		IdemixFlags target = new IdemixFlags(representation);

		assertEquals(flags, target.getPinProtectionMask());
		assertEquals(rfu, target.getRFU());
	}

	@Test
	public void packUnPackIssuanceSetupData() {
		Random rnd = new Random();

		short id = (short) rnd.nextInt();
		short size = (short) rnd.nextInt();

		short mask = (short) rnd.nextInt();
		byte rfu = (byte) rnd.nextInt();
		IdemixFlags flags = new IdemixFlags(mask, rfu);

		BigInteger context = new BigInteger(IssuanceSetupData.SIZE_CONTEXT * 8, rnd);
		int timestamp = rnd.nextInt();

		IssuanceSetupData orig = new IssuanceSetupData(id, size, flags, context, timestamp);
		byte[] representation = orig.getBytes();
		IssuanceSetupData target = new IssuanceSetupData(representation);

		assertEquals(id, target.getID());
		assertEquals(size, target.getSize());
		assertEquals(context, target.getContext());
		assertEquals(timestamp, target.getTimestamp());

		IdemixFlags target_flags = target.getFlags();
		assertEquals(mask, target_flags.getPinProtectionMask());
		assertEquals(rfu, target_flags.getRFU());
	}

}
