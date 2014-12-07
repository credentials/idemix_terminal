package org.irmacard.credentials.idemix.smartcard;

import java.util.Arrays;
import java.util.logging.Logger;


public class PinCode {
	private byte[] code;
	private boolean verified;
	private int tries_left;

	public enum PinCodeStatus {BLOCKED, CORRECT, WRONG_LENGTH, INCORRECT};
	public static final int DEFAULT_NUM_TRIES = 3;

	private final static Logger Log = Logger.getLogger(PinCode.class.getName());

    public static final byte[] DEFAULT_CRED_PIN = "0000".getBytes();
    public static final byte[] DEFAULT_CARD_PIN = "000000".getBytes();

    public static final int PIN_SIZE_INTERNAL = 8;

	public PinCode(byte[] code) {
		setPin(code);
		this.tries_left = DEFAULT_NUM_TRIES;
		this.verified = false;
	}

	public void setPin(byte[] pin) {
		code = new byte[PIN_SIZE_INTERNAL];
        System.arraycopy(pin, 0, code, 0, pin.length);
	}

	public void reset() {
		verified = false;
	}

	public boolean verified() {
		return verified;
	}

	public PinCodeStatus verify(byte[] attempt) {
		if (tries_left == 0) {
			Log.warning("Pin code blocked");
			return PinCodeStatus.BLOCKED;
		}

		if (attempt.length != PIN_SIZE_INTERNAL) {
			Log.warning("Pin length incorrect " + attempt.length + " " + code.length);
			return PinCodeStatus.WRONG_LENGTH;
		}

		if (Arrays.equals(code, attempt)) {
			Log.info("Pin verified");
			tries_left = DEFAULT_NUM_TRIES;
			verified = true;
			return PinCodeStatus.CORRECT;
		} else {
			tries_left = tries_left - 1;
			Log.warning("Pin incorrect " + tries_left + " tries left");
			verified = false;
			return PinCodeStatus.INCORRECT;
		}
	}

	public int getTriesLeft() {
		return tries_left;
	}
}
