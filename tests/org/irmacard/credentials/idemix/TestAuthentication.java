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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;

import javax.smartcardio.CardException;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.util.Hex;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.KeyFactory;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.util.BCECUtil;
import org.irmacard.credentials.cert.IRMACertificate;
import org.irmacard.credentials.cert.IRMACertificateBody;
import org.irmacard.idemix.IdemixService;
import org.junit.BeforeClass;
import org.junit.Test;


public class TestAuthentication {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private RSAPublicKey caKey;

	@BeforeClass
	public static void initializeInformation() {
		// TODO: initialize storage
		java.security.Security.addProvider(new com.sun.crypto.provider.SunJCE());
	}

	@Test
	public void testCertificateVerification() throws CardException, CardServiceException, NoSuchAlgorithmException, NoSuchProviderException, ConstructionException, InvalidKeyException, SignatureException, IOException, CertificateException {
		Certificate cert = constructCertificate();
		System.out.println("Cert (" + cert.getEncoded().length  + "): " + Hex.toHexString(cert.getEncoded()));
		cert.verify(caKey);
		CardService terminal = TestSetup.getCardService();
		IdemixService idemix = new IdemixService(terminal);
		idemix.open();
		//idemix.setCAKey(caKey);
		//idemix.verifyCertificate(cert);
	}

	private Certificate constructCertificate() throws NoSuchAlgorithmException, NoSuchProviderException, ConstructionException, InvalidKeyException, SignatureException, IOException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(1024, new SecureRandom());
        final KeyPair keyPair = keyGen.generateKeyPair();
        final KeyPair keyPair2 = keyGen.generateKeyPair();
        PrivateKey signerKey = keyPair2.getPrivate();
        caKey = (RSAPublicKey) keyPair2.getPublic();
        String algorithmName = "SHA1WITHRSAANDMGF1";

        CVCPublicKey cvcPublicKey = KeyFactory.createInstance(keyPair.getPublic(), algorithmName, null);

        final CAReferenceField caRef = new CAReferenceField("SE","PASS-CVCA","00111");
        final HolderReferenceField holderRef = new HolderReferenceField(caRef.getCountry(), caRef.getMnemonic(), caRef.getSequence());
        Calendar cal1 = Calendar.getInstance();
        Date validFrom = cal1.getTime();

        Calendar cal2 = Calendar.getInstance();
        cal2.add(Calendar.MONTH, 3);
        Date validTo = cal2.getTime();

        // Create the CVCertificateBody
        IRMACertificateBody body = new IRMACertificateBody(
              caRef,
              cvcPublicKey,
              holderRef,
              validFrom,
              validTo );

        IRMACertificate cvc = new IRMACertificate(body);

        // Perform signing
        Signature signature = Signature.getInstance(AlgorithmUtil.convertAlgorithmNameToCVC(algorithmName), "BC");
        signature.initSign(signerKey);
        System.out.println("TBS (" + cvc.getTBS().length + "): " + Hex.toHexString(cvc.getTBS()));
        signature.update(cvc.getTBS());
        byte[] signdata = signature.sign();

        // Now convert the X9.62 signature to a CVC signature
        byte[] sig = BCECUtil.convertX962SigToCVC(algorithmName, signdata);
        // Save the signature and return the certificate
        cvc.setSignature(sig);

		return new CardVerifiableCertificate(cvc);
	}
}
