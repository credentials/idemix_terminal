package service;

import java.util.Map;

import net.sourceforge.scuba.smartcards.ICommandAPDU;

/**
 * Simple data structure for storing APDU commands for smart cards
 * together with meta data.
 * 
 * @author Maarten Everts
 */
public class ProtocolCommand {
	
	/**
	 * A short string used to uniquely identify this command. 
	 */
	public String key;
	
	/**
	 * A brief description of the command.
	 */
	public String description;
	
	/**
	 * The actual command APDU to be send to the smart card.
	 */
	public ICommandAPDU command;

	/**
	 * A map to translate smart card status bytes to error strings, can be null.
	 */
	public Map<Integer,String> errorMap = null;
	
	/**
	 * Construct a new ProtocolCommand.
	 * 
	 * @param key used to identify this command.
	 * @param description of the command.
	 * @param apdu to be send to the smart card.
	 */
	public ProtocolCommand(String key, String description, ICommandAPDU apdu) {
		this.key = key;
		this.description = description;
		this.command = apdu;
	}
	
	/**
	 * Construct a new ProtocolCommand.
	 * 
	 * @param key used to identify this command.
	 * @param description of this command.
	 * @param apdu to be send to the smart card.
	 * @param error mapping from status bytes to error strings.
	 */
	public ProtocolCommand(String key, String description, ICommandAPDU apdu, Map<Integer,String> error) {
		this.key = key;
		this.description = description;
		this.command = apdu;
		this.errorMap = error;
	}
}
