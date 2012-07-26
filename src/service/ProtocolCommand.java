package service;

import java.util.HashMap;

import net.sourceforge.scuba.smartcards.CommandAPDU;

/**
 * Simple datastructure for storing APDU commands for smartcards
 * together with meta data.
 * @author maarten
 *
 */
public class ProtocolCommand {
	public String key;
	public String description;	
	public CommandAPDU command;

	/**
	 * The errorMap maps smartcard status bytes to error strings, can be null.
	 */
	public HashMap<Integer,String> errorMap = null;
	
	public ProtocolCommand(String key, String description, CommandAPDU command) {
		this.key = key;
		this.description = description;
		this.command = command;
	}
	public ProtocolCommand(String key, String description, CommandAPDU command, HashMap<Integer,String> errorMap) {
		this.key = key;
		this.description = description;
		this.command = command;
		this.errorMap = errorMap;
	}
}
