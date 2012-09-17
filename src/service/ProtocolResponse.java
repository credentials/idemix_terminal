package service;

import net.sourceforge.scuba.smartcards.IResponseAPDU;

/**
 * Simple data structure for storing APDU responses from smart cards.
 * 
 * @author Wouter Lueks
 */
public class ProtocolResponse {
	
	/**
	 * A short string used to uniquely identify this command. 
	 */	
	private String key;
	
	/**
	 * The actual response APDU received from the smart card.
	 */	
	private IResponseAPDU response;

	/**
	 * Construct a new ProtocolResponse.
	 * 
	 * @param key used to identify the response.
	 * @param response from the smart card.
	 */
	public ProtocolResponse(String key, IResponseAPDU response) {
		this.key = key;
		this.response = response;
	}
	
	/**
	 * Get the key used to identify this response.
	 * 
	 * @return the key used to identify this response. 
	 */
	public String getKey () {
		return key;
	}
	
	/**
	 * Get the response APDU received from the smart card.
	 * 
	 * @return the response from the smart card.
	 */
	public IResponseAPDU getResponse () {
		return response;
	}
	
	/**
	 * Set the response from the smart card.
	 * 
	 * @param apdu received from the smart card.
	 */
	public void setResponse(IResponseAPDU apdu) {
		this.response = apdu;
	}
}
