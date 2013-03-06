package org.irmacard.idemix.tests;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.TerminalCardService;

import org.irmacard.idemix.IdemixService;
import org.junit.Test;

public class TestLog {
    public static final byte[] DEFAULT_CARD_PIN = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
	
	@Test
	public void testRetrieveLog() throws CardException, CardServiceException {
        CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);            
        IdemixService is = new IdemixService(new TerminalCardService(terminal));
        
        is.open();
        is.sendCardPin(DEFAULT_CARD_PIN);
        is.getLogEntries();
	}

}
