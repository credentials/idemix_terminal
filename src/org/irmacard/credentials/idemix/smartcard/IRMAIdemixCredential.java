/**
 * IRMAIdemixCredential.java
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, December 2014.
 */

package org.irmacard.credentials.idemix.smartcard;

import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.idemix.util.IdemixFlags;

public class IRMAIdemixCredential {
	private IdemixFlags userFlags;
	private IdemixFlags issuerFlags;
	private IdemixCredential cred;

	public IRMAIdemixCredential(IdemixFlags issuerFlags) {
		this.issuerFlags = issuerFlags;
		this.userFlags = new IdemixFlags();
	}

	public void setUserFlags(IdemixFlags userFlags) {
		this.userFlags = userFlags;
	}

	public IdemixFlags getUserFlags() {
		return userFlags;
	}

	public IdemixFlags getIssuerFlags() {
		return issuerFlags;
	}

	public void setCredential(IdemixCredential cred) {
		this.cred = cred;
	}

	public IdemixCredential getCredential() {
		return cred;
	}
}
