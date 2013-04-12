package org.irmacard.idemix.util;

public class IdemixFlags {

	private short pinProtectionMask;
	private byte RFU;
	
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
		return (short) ((array[idx] << 8) + array[idx + 1]);
	}
	
	private static byte[] putShortAt(byte[] array, int idx, int value) {
		array[idx] = (byte) (value >> 8);
		array[idx + 1] = (byte) (value & 0xff);
		return array;
	}
}
