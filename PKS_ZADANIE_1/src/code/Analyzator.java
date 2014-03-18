package code;

import gui.Gui;

import java.io.File;
import java.util.ArrayList;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;

public class Analyzator {

	static protected File subor;
	static protected String obsah;
	
	protected final static StringBuilder errbuf = new StringBuilder();
	protected final static String ethernet = "Ethernet II";
	protected static int id = 1;
	
	protected static ArrayList<IpZaznam> ip_list = new ArrayList<IpZaznam>();
	protected static ArrayList<Komunikacia> komunikacie = new ArrayList<Komunikacia>();
	
	protected static Pcap pcap;
	
	public static int analyza() throws Exception {
	    Gui.vypis("Analyza suboru " + subor.getName() + "\n");
		
	    pcap = Pcap.openOffline(subor.getAbsolutePath(), errbuf);
	    if (pcap == null) {
	    	Gui.vypis("Chyba pri nacitani suboru\n");
	    	return 1;
	    }
	    
	    pcap.loop(-1, new JPacketHandler<StringBuilder>() { 
	    	public void nextPacket(JPacket packet, StringBuilder errbuf) {
	    		String typ = typ(packet);
	    		
	    		Gui.vypis("No:              " + packet.getFrameNumber() + "\n");
	    		Gui.vypis("Zachytena dlzka: " + packet.getCaptureHeader().caplen() + "\n");
	    		Gui.vypis("Dlzka po mediu:  " + ((packet.getCaptureHeader().wirelen() < 64)? 64: packet.getCaptureHeader().wirelen()) + "\n");
	    		Gui.vypis("Typ:             " + typ + "\n");
	    		Gui.vypis("Source MAC:      " + srcMac(packet) + "\n");
	    		Gui.vypis("Destination MAC: " + dstMac(packet) + "\n");
	    		
	    		Gui.vypis(hexPacket(packet) + "\n\n");
	    		
	    		analyzaIp(packet, typ);
	    	
	    	}
	    }, errbuf);
	    
	    vypisIp();
		return 0;
	}
	
	public static int komunikacie(final int index) {
	    Gui.vypis("Analyza komunikacii v subore " + subor.getName() + "\n" +
	    		  "Uloha: " + Gui.getCmbText(index) + ".\n");
		
	    pcap = Pcap.openOffline(subor.getAbsolutePath(), errbuf);
	    
	    if (pcap == null) {
	    	Gui.vypis("Chyba pri nacitani suboru\n");
	    	return 1;
	    }
	    
	    pcap.loop(-1, new JPacketHandler<StringBuilder>() { 
	    	public void nextPacket(JPacket packet, StringBuilder errbuf) {
	    		String typ = typ(packet);
	    		
				analyzaIp(packet, typ);
	    		
	    		if (typ == ethernet) {
	    			int etherType = getEtherType(packet);
	    			
	    			switch (etherType) {
		    			case 2048: // 0800 IPv4
		    				
		    				switch (getProtocol(packet)) {
			    				case 6: // 06 TCP
			    				case 11: // 11 UDP
			    					
			    					int srcPort = getSrcPort(packet);
			    	    			int dstPort = getDstPort(packet);
			    					
			    					switch(index) {
				    	    			case 2: //http
				    	    				if (srcPort == 80 || dstPort == 80) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    	    				break;
				    	    			case 3: //https
				    	    				if (srcPort == 443 || dstPort == 443) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    	    				break;
				    	    			case 4: //telnet
				    	    				if (srcPort == 23 || dstPort == 23) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    	    				break;
				    	    			case 5: //ssh
				    	    				if (srcPort == 22 || dstPort == 22) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    	    				break;
				    	    			case 6: //FTP riadiace
				    	    				if (srcPort == 21 || dstPort == 21) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    	    				break;
				    	    			case 7: //FTP datove
				    	    				if (srcPort == 20 || dstPort == 20) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    	    				break;
				    	    			case 8: //TFTP
				    	    				if (srcPort == 69 || dstPort == 69) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    	    				break;
				    	    			case 9: //ICMP
				    	    				break;
				    	    			case 10: //ARP
				    	    				break;
				    	    			default:
				    	    				break;
			    	    			}
			    					break;
			    				case 1: // 01 ICMP
			    					//analyza ICMP protokolu
			    					break;
			    				default: 
			    					break;
		    				}
		    				break;
		    			case 34525: // 86DD IPv6
		    				//ICMPv6
		    				break;
		    			case 2054: // 0806 ARP
		    				//ARP dvojice
		    				break;
		    			default:
		    				break;
	    			}
	    			
	    		}
	    	}
	    }, errbuf);
	    
	    vypisKomunikacie();
	    
		return 0;
	}
	
	private static void vypisPacket(JPacket p) {
		Gui.vypis("No:              " + p.getFrameNumber() + "\n");
		Gui.vypis("Zachytena dlzka: " + p.getCaptureHeader().caplen() + "\n");
		Gui.vypis("Dlzka po mediu:  " + p.getCaptureHeader().wirelen() + "\n");
		Gui.vypis("Typ:             " + typ(p) + "\n");
		Gui.vypis("Source MAC:      " + srcMac(p) + "\n");
		Gui.vypis("Destination MAC: " + dstMac(p) + "\n");
		Gui.vypis("Src Port: " + getSrcPort(p) + "\n");
		Gui.vypis("Dst Port: " + getDstPort(p) + "\n");
		Gui.vypis(hexPacket(p) + "\n\n");
	}
	
	private static void vypisKomunikacie() {
		boolean gotIt = false;
		
		//1. kompletna komunikacia
		for (Komunikacia k: komunikacie) {
			if (k.hasStart() && k.hasEnd()) {
				gotIt = true;
				Gui.vypis("================================================\n");
				Gui.vypis("Kompletna komunikacia\n");
				Gui.vypis("================================================\n");
				Gui.vypis("Klient: " + k.getSource() + ":" + getSrcPort(k.getPacketList().get(0)) + "\n");
				Gui.vypis("Server: " + k.getDestination() + ":" + getDstPort(k.getPacketList().get(0)) + "\n");
				Gui.vypis("Pocet ramcov: " + k.getPacketList().size() + "\n");
				
				if (k.getPacketList().size() > 20) {
					for (int i = 0; i < 10; ++i) {
						JPacket p = k.getPacketList().get(i);
						vypisPacket(p);
					}
					
					Gui.vypis(".\n.\n.\n\n");
					
					for (int i = k.getPacketList().size() - 10; i < k.getPacketList().size(); ++i) {
						JPacket p = k.getPacketList().get(i);
						vypisPacket(p);
					}
				}
				else {
					for (JPacket p: k.getPacketList())
						vypisPacket(p);
					break;
				}
			}
		}
		
		if (!gotIt) {
			Gui.vypis("================================================\n");
			Gui.vypis("Kompletna komunikacia neexistuje.\n");
			Gui.vypis("================================================\n");
		}
		
		gotIt = false;
		
		//1. nekompletna komunikacia
		for (Komunikacia k: komunikacie) {
			if (k.hasStart() && !k.hasEnd()) {
				gotIt = true;
				Gui.vypis("================================================\n");
				Gui.vypis("Nekompletna komunikacia\n");
				Gui.vypis("================================================\n");
				Gui.vypis("Klient: " + k.getSource() + ":" + getSrcPort(k.getPacketList().get(0)) + "\n");
				Gui.vypis("Server: " + k.getDestination() + ":" + getDstPort(k.getPacketList().get(0)) + "\n");
				Gui.vypis("Pocet ramcov: " + k.getPacketList().size() + "\n");
				
				if (k.getPacketList().size() > 20) {
					for (int i = 0; i < 10; ++i) {
						JPacket p = k.getPacketList().get(i);
						vypisPacket(p);
					}
					
					Gui.vypis(".\n.\n.\n\n");
					
					for (int i = k.getPacketList().size() - 10; i < k.getPacketList().size(); ++i) {
						JPacket p = k.getPacketList().get(i);
						vypisPacket(p);
					}
				}
				else {
					for (JPacket p: k.getPacketList())
						vypisPacket(p);
					break;
				}
			}
		}
		
		if (!gotIt) {
			Gui.vypis("================================================\n");
			Gui.vypis("Nekompletna komunikacia neexistuje.\n");
			Gui.vypis("================================================\n");
		}
		
	}

	protected static void spracujKomunikaciu(JPacket packet) {
	
		String source = getSrcIP(packet);
		String destination = getDstIP(packet);
		int sourcePort = getSrcPort(packet);
		int destPort = getDstPort(packet);
		
		boolean zhoda = false;
		
		//ak je prazdny zoznam komunikacii
		if (komunikacie.isEmpty()) {
			komunikacie.add(new Komunikacia(id, source, destination, 80, sourcePort, destPort, false, false));
			
			zhoda = addPacketToComm(source, destination, sourcePort, destPort, packet);
			
			id++;
			return;
		}
		
		//ak nie je prazdny hladame zhodu
		zhoda = addPacketToComm(source, destination, sourcePort, destPort, packet);
		
		//ak sa nenasla zhoda 
		if (zhoda == false) {
			komunikacie.add(new Komunikacia(id, source, destination, 80, sourcePort, destPort, false, false));
			
			addPacketToComm(source, destination, sourcePort, destPort, packet);
			
			id++;
			return;
		}	
	}

	private static boolean addPacketToComm(String source, String destination, int srcPort, int dstPort, JPacket packet) {
		for (Komunikacia k: komunikacie) {
			if (( (source.equals(k.getSource()) && destination.equals(k.getDestination()))   || 
				  (source.equals(k.getDestination()) && destination.equals(k.getSource())) ) &&
				( (srcPort == k.getPortSrc() && dstPort == k.getPortDst())			 ||
				  (dstPort == k.getPortSrc() && srcPort == k.getPortDst()) )		 &&
				  (k.hasEnd() == false) ) {
				k.addToPacketList(packet);
				return true;
			}	
		}
		
		return false;
	}
	
	private static void setStartEnd(){
		for (Komunikacia  k: komunikacie) {
			if (!k.hasStart())
				checkStart(k);
			if (!k.hasEnd())
				checkEnd(k);
		}
	}

	private static void checkEnd(Komunikacia k) {
		boolean fin1 = false, fin2 = false;
		int listSize = k.getPacketList().size();
		
		if (listSize > 3) {
			
			//rst komunikacie
			for (int i = 0; i < listSize; ++i) {
				if ((k.getPacketList().get(i).getUByte(47) & (1 << 2)) == 4) {
					k.setEnd(true);
					return;
				}
			}
			
			String source = "", dest = "";
			
			for (int i = 0; i < listSize; ++i) {
				int biti = (k.getPacketList().get(i).getUByte(47) & 1);
				String tmpSrci = getSrcIP(k.getPacketList().get(i));
				String tmpDsti = getDstIP(k.getPacketList().get(i));
				
				if ((biti == 1)) {
					source = tmpSrci;
					dest = tmpDsti;
					
					for (int j = i + 1; j < listSize; ++j) {
						int bitj = (k.getPacketList().get(j).getUByte(47) & (1 << 4));
						String tmpSrcj = getSrcIP(k.getPacketList().get(j));
						String tmpDstj = getDstIP(k.getPacketList().get(j));
					
						if ((bitj == 16) && tmpSrci.equals(tmpDstj) && tmpDsti.equals(tmpSrcj)) {
							fin1 = true;
							break;
						}
					}
				}
				
				if (fin1)
					break;
			}
			
			//ak nenasiel ziadny fin nema zmysel pokracovat
			if (source.equals("") || dest.equals(""))
				return;
			
			for (int i = 0; i < listSize; ++i) {
				int biti = (k.getPacketList().get(i).getUByte(47) & 1);
				String tmpSrci = getSrcIP(k.getPacketList().get(i));
				String tmpDsti = getDstIP(k.getPacketList().get(i));
				
				if ((biti == 1) && tmpSrci.equals(dest) && tmpDsti.equals(source)) {
					for (int j = i + 1; j < listSize; ++j) {
						int bitj = (k.getPacketList().get(j).getUByte(47) & (1 << 4));
						String tmpSrcj = getSrcIP(k.getPacketList().get(j));
						String tmpDstj = getDstIP(k.getPacketList().get(j));
						
						if ((bitj == 16) && tmpSrcj.equals(source) && tmpDstj.equals(dest)) {
							fin2 = true;
							break;
						}
					}
				}
				
				if (fin2)
					break;
			}
		}
		
		if (fin1 && fin2)
			k.setEnd(true);
	}

	private static void checkStart(Komunikacia k) {
		int syn, synack, ack;
		
		if (k.getPacketList().size() > 3) {
			for (int i = 1; i < k.getPacketList().size() - 1; ++i) {
				syn = k.getPacketList().get(i - 1).getUByte(47);
				synack = k.getPacketList().get(i).getUByte(47);
				ack = k.getPacketList().get(i + 1).getUByte(47);
				
				if ((syn == 2) && (synack == 18) & (ack == 16)) // 2, 12, 10 hexa
					k.setStart(true);
			}
		}
	}

	private static String getSrcIP(JPacket packet) {
		return new String(String.format("%d.%d.%d.%d", packet.getUByte(26), packet.getUByte(27), packet.getUByte(28), packet.getUByte(29)));
	}
	
	private static String getDstIP(JPacket packet) {
		return new String(String.format("%d.%d.%d.%d", packet.getUByte(30), packet.getUByte(31), packet.getUByte(32), packet.getUByte(33)));
	}

	protected static int getProtocol(JPacket packet) {
		return packet.getUByte(23);
	}

	protected static int getDstPort(JPacket packet) {
		return packet.getUShort(36);
	}

	protected static int getSrcPort(JPacket packet) {
		return packet.getUShort(34);
	}

	protected static int getEtherType(JPacket packet) {
		return packet.getUShort(12);
	}

	public static void vymazZoznamIp() {
		while (ip_list.size() > 0)
			ip_list.remove(ip_list.size() - 1);
	}
	
	public static void vymazZoznamKom() {
		while (komunikacie.size() > 0)
			komunikacie.remove(komunikacie.size() - 1);
		
		id = 1;
	}
	
	public static void pridajIp(String ip, int bajt) {
		for (IpZaznam z: ip_list)
			if (z.getIp().equals(ip)) {
				z.incBajty(bajt);
				return;
			}
		
		ip_list.add(new IpZaznam(ip, bajt));
	}
	
	public static void vypisIp() {
		int max = -1;
		
		Gui.vypis("==================================================\n");
		Gui.vypis("Source IP adresy: \n");
		
		for (IpZaznam z: ip_list) {
			Gui.vypis(z.getIp() + "\t" + z.getBajty() + " B \n");
			if (z.getBajty() > max)
				max = z.getBajty();
		}
		
		Gui.vypis("Adresa IP s najvacsim poctom odvysielanych bajtov:\n");
		
		for (IpZaznam z: ip_list) {
			if (z.getBajty() == max)
				Gui.vypis(z.getIp() + "\t" + z.getBajty() + " B \n");
		}
	}
	
	public static String zistiIp(JPacket packet) {
		String ip = "";
		
		ip += String.format("%d.", packet.getUByte(26));
		ip += String.format("%d.", packet.getUByte(27));
		ip += String.format("%d.", packet.getUByte(28));
		ip += String.format("%d", packet.getUByte(29));
		
		return ip;
	}
	
	public static void analyzaIp(JPacket packet, String typ) {
		if (typ != "Ethernet II")
			return;
		else {
			int ether = packet.getUShort(12);
			
			switch (ether) {
			case 2054: // 08 06 ARP
				//
				break;
			case 2048: // 08 00 IPv4
				pridajIp(zistiIp(packet), packet.getCaptureHeader().caplen());
				break;
			case 2269: // 08 DD IPv6
				//
				break;
			default:
				break;
			}
			
		}
	}
	
	public static String typ(JPacket packet) {
		String typ = "neznamy";
		
		int etherType = packet.getUShort(12);
		
		if (etherType >= 1536)
			typ = "Ethernet II";
		else if (etherType >= 0 && etherType <= 1500) {
			int typ802_3 = packet.getUShort(14);
			typ = "802.3";
					
			if (typ802_3 == 65535) {
				typ = "802.3 RAW";
				return typ;
			}
			else if (typ802_3 == 43690) {
				typ = "802.3 SNAP";
				return typ;
			}
			else {
				typ = "802.3 LLC";
				return typ;
			}
		}
			
		return typ;
	}
	
	public static String srcMac(JPacket packet) {
		String mac = "";
		
		for (int i = 6; i < 11; ++i)
			mac += String.format("%02X:", packet.getUByte(i) & 0xFF);
		
		mac += String.format("%02X", packet.getUByte(11) & 0xFF);
		
		return mac;
	}
	
	public static String dstMac(JPacket packet) {
		String mac = "";
		
		for (int i = 0; i < 5; ++i)
			mac += String.format("%02X:", packet.getUByte(i) & 0xFF);
		
		mac += String.format("%02X", packet.getUByte(5) & 0xFF);
		
		return mac;
	}
	
	public static String hexPacket(JPacket packet) {
		int len = packet.getPacketWirelen();
		String vystup = "";
		
		for (int i = 1; i <= len; ++i) {
			if (i % 16 == 0)
				vystup += String.format("%02X\n", packet.getUByte(i - 1) & 0xFF);
			else if (i % 8 == 0)
				vystup += String.format("%02X  ", packet.getUByte(i - 1) & 0xFF);
			else
				vystup += String.format("%02X ", packet.getUByte(i - 1) & 0xFF);
		}
		
		return vystup;
	}
	
	public static File getSubor() {
		return subor;
	}

	public static void setId(int value) {
		id = value;
	}
	
	public static void setSubor(File subor) {
		Analyzator.subor = subor;
	}
	
}
