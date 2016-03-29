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

package org.irmacard.credentials.idemix;

import javax.smartcardio.CardException;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.descriptions.IdemixVerificationDescription;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.idemix.IdemixService;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;

public class TestCardHelpers {

    public static void issue(String issuer, String credential, Attributes attributes,
            CardService cs) throws InfoException, CardException, CredentialsException,
                    CardServiceException {
        CredentialDescription cd = DescriptionStore.getInstance()
                .getCredentialDescriptionByName(TestIRMACredential.schemeManager, issuer, credential);
        issue(cd, attributes, cs);
    }

    private static void issue(CredentialDescription cd, Attributes attributes,
            CardService cs) throws InfoException, CardException, CredentialsException,
                    CardServiceException {
        IdemixService is = new IdemixService(cs);
        IdemixCredentials ic = new IdemixCredentials(is);
        ic.connect();
        is.sendPin(TestSetup.DEFAULT_CRED_PIN);
        ic.issue(cd, IdemixKeyStore.getInstance().getSecretKey(cd), attributes, null);
        is.close();
    }

    public static Attributes verify(String verifier, String verification_spec,
            CardService cs) throws CardException, CredentialsException, InfoException {
        IssuerIdentifier verifierId = new IssuerIdentifier(TestIRMACredential.schemeManager, verifier);
        return verify(new IdemixVerificationDescription(verifierId, verification_spec), cs);
    }

    private static Attributes verify(IdemixVerificationDescription vd, CardService cs)
            throws CardException, CredentialsException {
        IdemixCredentials ic = new IdemixCredentials(cs);

        Attributes attr = ic.verify(vd);
        cs.close();
        return attr;
    }

    public static void remove(String issuer, String credential, CardService cs)
            throws InfoException, CardException, CredentialsException,
            CardServiceException {
        CredentialDescription cd = DescriptionStore.getInstance()
                .getCredentialDescriptionByName(TestIRMACredential.schemeManager, issuer, credential);

        remove(cd, cs);
    }

    private static void remove(CredentialDescription cd, CardService cs)
            throws CardException, CredentialsException, CardServiceException,
            InfoException {
        IdemixService is = new IdemixService(cs);
        IdemixCredentials ic = new IdemixCredentials(is);

        ic.connect();
        is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
        try {
            ic.removeCredential(cd);
        } catch (CardServiceException e) {
            if (!e.getMessage().toUpperCase().contains("6A88")) {
                throw e;
            }
        }
        is.close();
    }
}
