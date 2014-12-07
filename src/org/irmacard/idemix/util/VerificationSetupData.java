package org.irmacard.idemix.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.irmacard.idemix.IdemixSmartcard;

public class VerificationSetupData {
	// TODO: reference IdemixSystemParameters after fixing dependencies
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
	
	public VerificationSetupData(byte[] data) {
		ByteBuffer buffer = ByteBuffer.wrap(data);

		cred_id = buffer.getShort();
		mask = buffer.getShort();
		
		byte[] raw_context = new byte[SIZE_CONTEXT];
		buffer.get(raw_context);
		context = new BigInteger(1, raw_context);
		
		timestamp = buffer.getInt();
	}

	public byte[] getBytes() {
		ByteBuffer buffer = ByteBuffer.allocate(SIZE);
		
		return buffer.putShort(cred_id).putShort(mask)
				.put(IdemixSmartcard.fixLength(context, SIZE_CONTEXT * 8))
				.putInt(timestamp).array();
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
