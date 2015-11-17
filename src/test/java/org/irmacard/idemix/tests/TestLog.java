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

package org.irmacard.idemix.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Date;
import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.TerminalCardService;
import org.irmacard.idemix.IdemixService;
import org.irmacard.idemix.util.IdemixLogEntry;
import org.junit.Test;

public class TestLog {
    public static final byte[] DEFAULT_CARD_PIN = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30};

	public static final byte[] test_input = { 0x51, 0x39, (byte) 0x8b, (byte) 0xb6, 0x00,
			0x00, 0x00, 0x00, 0x02, 0x00, 0x0A, 0x00, 0x3E, 0x00, 0x00, 0x00 };

    @Test
    public void parseLog() {
    	IdemixLogEntry log = new IdemixLogEntry(test_input);
    	assertTrue((log.getAction() == IdemixLogEntry.Action.VERIFY));
    	assertEquals(log.getTimestamp().getTime(), (new Date(1362725814000l)).getTime());
    	assertEquals(log.getCredential(), 10);
    	assertEquals(log.getDisclose(), 0x3E);
    }

	@Test
	public void testRetrieveLog() throws CardException, CardServiceException {
        CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);            
        IdemixService is = new IdemixService(new TerminalCardService(terminal));
        
        is.open();
        is.sendCardPin(DEFAULT_CARD_PIN);
        List<IdemixLogEntry> list = is.getLogEntries();
        for(IdemixLogEntry l : list) {
        	l.print();
        }
	}
}
