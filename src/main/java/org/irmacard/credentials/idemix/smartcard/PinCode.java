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
