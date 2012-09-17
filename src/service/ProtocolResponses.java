package service;

import java.util.HashMap;

import net.sourceforge.scuba.smartcards.IResponseAPDU;

/**
 * Simple type declaration for a Map containing responses to protocol commands.
 * 
 * @author Wouter Lueks
 */
public class ProtocolResponses extends HashMap<String, IResponseAPDU> {

	private static final long serialVersionUID = 1L;
	
}
