package org.irmacard.credentials.idemix.smartcard;

import org.irmacard.idemix.util.VerificationSetupData;

public interface VerificationStartListener {
	public void verificationStarting(VerificationSetupData data);
}
