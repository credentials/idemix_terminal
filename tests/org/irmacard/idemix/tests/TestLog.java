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

import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.TerminalCardService;

import org.irmacard.idemix.IdemixService;
import org.irmacard.idemix.util.IdemixLogEntry;
import org.junit.Test;

public class TestLog {
    public static final byte[] DEFAULT_CARD_PIN = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
	
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
