package code;

import java.util.ArrayList;

import org.jnetpcap.packet.JPacket;

public class Komunikacia {
	protected int id;
	
	protected String source;
	protected String destination;
	
	protected int protocol;
	protected int portSrc;
	protected int portDst;
	
	protected boolean start;
	protected boolean end;
	
	protected ArrayList<JPacket> packetList = new ArrayList<JPacket>();
	protected int packetSize[] = {0, 0, 0, 0, 0, 0, 0, 0};	//0-19, 20-39, 40-79, 80-159, 160-319, 320-639, 640-1279, 1280-*

	public Komunikacia(int id, String source, String destination, int protocol, int portSrc, int portDst, boolean start, boolean end) {
		this.id = id;

		this.source = source;
		this.destination = destination;
		
		this.protocol = protocol;
		this.portSrc = portSrc;
		this.portDst = portDst;
		
		this.start = start;
		this.end = end;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public String getDestination() {
		return destination;
	}

	public void setDestination(String destination) {
		this.destination = destination;
	}

	public int getProtocol() {
		return protocol;
	}

	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}

	public int getPortSrc() {
		return portSrc;
	}

	public void setPortSrc(int portSrc) {
		this.portSrc = portSrc;
	}

	public int getPortDst() {
		return portDst;
	}

	public void setPortDst(int portDst) {
		this.portDst = portDst;
	}

	public boolean hasEnd() {
		return end;
	}

	public void setEnd(boolean end) {
		this.end = end;
	}

	public boolean hasStart() {
		return start;
	}

	public void setStart(boolean start) {
		this.start = start;
	}

	public ArrayList<JPacket> getPacketList() {
		return packetList;
	}

	public void addToPacketList(JPacket packet) {
		this.packetList.add(packet);
	}

	public void updateSizeList(int wireSize) {
		//0-19, 20-39, 40-79, 80-159, 160-319, 320-639, 640-1279, 1280-*
		if (wireSize < 19)
			packetSize[0]++;
		else if (wireSize < 39)
			packetSize[1]++;
		else if (wireSize < 79)
			packetSize[2]++;
		else if (wireSize < 159)
			packetSize[3]++;
		else if (wireSize < 319)
			packetSize[4]++;
		else if (wireSize < 639)
			packetSize[5]++;
		else if (wireSize < 1279)
			packetSize[6]++;
		else
			packetSize[7]++;
	}
	
	public int getSizeListItem(int i) {
		return packetSize[i];
	}
}
