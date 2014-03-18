package code;

public class IpZaznam {
	protected String ip;
	protected int bajty;
	
	public IpZaznam(String ip, int bajt) {
		this.ip = ip;
		this.bajty = bajt;
	}

	public int getBajty() {
		return bajty;
	}
	
	public void setBajty(int bajty) {
		this.bajty = bajty;
	}
	
	public String getIp() {
		return ip;
	}
	
	public void setIp(String ip) {
		this.ip = ip;
	}
	
	public void incBajty(int bajt) {
		this.bajty += bajt;
	}
}
