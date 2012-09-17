package service;

import net.sourceforge.scuba.smartcards.IResponseAPDU;

public class ProtocolResponse {
	private String key;
	private IResponseAPDU response;

	public ProtocolResponse(String key, IResponseAPDU response) {
		this.key = key;
		this.response = response;
	}
	
	public String getKey () {
		return key;
	}
	
	public IResponseAPDU getResponse () {
		return response;
	}
	
	public void setResponse (IResponseAPDU response) {
		this.response = response;
	}
}
