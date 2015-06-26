/**
 * TestLog.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, March 2013.
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
