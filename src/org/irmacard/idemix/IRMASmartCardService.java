package org.irmacard.idemix;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.VerificationDescription;
import org.irmacard.credentials.keys.PrivateKey;

public interface IRMASmartCardService {
	public Attributes verify(VerificationDescription desc);
	public void issue(CredentialDescription cred, Attributes attrs, PrivateKey sk);
}
