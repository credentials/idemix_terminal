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
