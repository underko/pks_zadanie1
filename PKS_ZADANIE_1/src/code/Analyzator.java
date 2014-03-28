package code;

import gui.Gui;

import java.io.BufferedReader;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
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
	protected static ArrayList<Tftp> tftp = new ArrayList<Tftp>();
	
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
	    		Gui.vypis("Dlzka po mediu:  " + wireSize(packet) + "\n");
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

	    int port_n = 0;
	    
		switch (index) {
    		case 0:
    		case 1:
    			break;
    		case 2:
    			port_n = getPortNumberFromFile("http");
    			break;
    		case 3:
    			port_n = getPortNumberFromFile("https");
    			break;
    		case 4:
    			port_n = getPortNumberFromFile("telnet");
    			break;
    		case 5:
    			port_n = getPortNumberFromFile("ssh");
    			break;
    		case 6:
    			port_n = getPortNumberFromFile("ftp control");
    			break;
    		case 7:
    			port_n = getPortNumberFromFile("ftp data");
    			break;
    		case 8:
    			port_n = getPortNumberFromFile("tftp");
    			break;
    		case 9:
    			port_n = 9;		//oznacenie pre spracovanie
    			break;
    		case 10:
    			port_n = 10;	//oznacenie pre spracovanie
    			break;
    		default:
    			break;
		}
	    
		final String parseString = String.valueOf(port_n);
		
	    pcap.loop(-1, new JPacketHandler<StringBuilder>() { 
	    	public void nextPacket(JPacket packet, StringBuilder errbuf) {
	    		String typ = typ(packet);
	    		final int portFinal = Integer.parseInt(parseString);
	    		
	    		if (typ == ethernet) {
	    			int etherType = getEtherType(packet);
	    			
	    			switch (etherType) {
		    			case 2048: // 0800 IPv4
		    				if (index > 1 && index < 10) {
			    				switch (getProtocol(packet)) {
				    				case 6: // 06 TCP
				    					if (index > 1 && index < 9) {
					    					int srcPort = getSrcPort(packet);
					    	    			int dstPort = getDstPort(packet);
					    	    			
					    	    			if (srcPort == portFinal || dstPort == portFinal) {
				    	    					spracujKomunikaciu(packet);
				    	    					setStartEnd();
				    	    				}
				    					}
				    					break;
				    				case 17: // 11 UDP
				    					if (index == 8) {
				    						//spracuj tftp (udp)
				    						int optcode = packet.getUShort(42);
				    						
				    						if (optcode >= 1 && optcode <= 5) {
				    							spracujTftp(packet);
				    							System.out.println("tftp: " + (id - 1) + " optcode: " + optcode + "\n");
				    						}
				    					}
				    					break;
				    				case 1: // 01 ICMP
				    					//analyza ICMP protokolu
				    					if (index == 9) {
				    						spracujICMP(packet);
				    						kontrolaICMP();
				    					}
				    					break;
				    				default: 
				    					break;
			    				}
		    				}
		    				break;
		    			case 34525: // 86DD IPv6
		    				//ICMPv6
		    				break;
		    			case 2054: // 0806 ARP
		    				//ARP dvojice
		    				if (index == 10) {
		    					spracujARP(packet);
		    				}
		    				break;
		    			default:
		    				break;
	    			}
	    			
	    		}
	    	}

	    }, errbuf);
	    
	    if (index == 10) {
	    	vypisArpKom();
	    }
	    else if (index == 9) {
	    	vypisIcmpKom();
	    }
	    else if (index == 8) {
	    	vypisTftpKom();
	    }
	    else {
	    	vypisKomunikacie();
	    }
	    
		return 0;
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
	
	protected static void spracujTftp(JPacket packet) {
		
		String source = getSrcIP(packet);
		String destination = getDstIP(packet);
		int sourcePort = getSrcPort(packet);
		int destPort = getDstPort(packet);
		int typ = packet.getUShort(42);
		
		boolean zhoda = false;
		
		if (destPort == 69) {	//nova komunikacia opcode 1(rrq), 2(wrq)
			tftp.add(new Tftp(id, source, destination, typ, sourcePort, -1, true, false));
			System.out.println(String.format("dst: 69\nsrc: %s\ndst: %s\nsrcP: %d\ndstP: %d\n", source, destination, sourcePort, -1));
			
			for (Tftp t: tftp) {
				if (t.getId() == id) {
					t.getPacketList().add(packet);
					id++;
					break;
				}
			}
		}
		else {	//data(3)/ack(4)/error(5)
			if (typ == 3) {
				//packet s datami
				zhoda = addTftpPacket(source, destination, sourcePort, destPort, packet);
				if (!zhoda)
					System.out.println("tftp: no match data\n");
			}
			else if (typ == 4) {
				//potvrdzujuci packet
				zhoda = addTftpPacket(source, destination, sourcePort, destPort, packet);
				if (!zhoda)
					System.out.println("tftp: no match ack\n");
			}
			else if (typ == 5) {
				//error bs
				zhoda = addTftpPacket(source, destination, sourcePort, destPort, packet);
				if (!zhoda)
					System.out.println("tftp: no match error\n");
			}
			
		}
	}
	
	private static void spracujICMP(JPacket packet) {
		
		String source = getSrcIP(packet);
		String destination = getDstIP(packet);
		int type = packet.getUByte(34);
		int code = packet.getUByte(35);
		
		boolean zhoda = false;
		
		if (komunikacie.isEmpty()) {
			komunikacie.add(new Komunikacia(id++, source, destination, 1, 0, 0, true, false));
			zhoda = addPacketToComm(source, destination, 0, 0, packet);
		}
		else {
			if (type == 8) {
				komunikacie.add(new Komunikacia(id++, source, destination, 1, 0, 0, true, false));
				zhoda = addPacketToComm(source, destination, 0, 0, packet);
			}
			else if (type == 0) {
				zhoda = addPacketToComm(source, destination, 0, 0, packet);
				
				if (!zhoda) {
					komunikacie.add(new Komunikacia(id++, source, destination, 1, 0, 0, false, true));
					zhoda = addPacketToComm(source, destination, 0, 0, packet);
				}
			}
			else {
				zhoda = addPacketToComm(source, destination, 0, 0, packet);
				
				if (!zhoda) {
					komunikacie.add(new Komunikacia(id++, source, destination, 1, 0, 0, false, false));
					zhoda = addPacketToComm(source, destination, 0, 0, packet);
				} 
			}
		}
		
		System.out.println(String.format("src: %s\ndst: %s\ntype: %d\tcode: %d\nzhoda: %s\npocet: %d\n\n", source, destination, type, code, zhoda, komunikacie.size()));
	}
	
	private static void spracujARP(JPacket packet) {
		int typ = packet.getUShort(20);
		
		if(typ == 1) {
			komunikacie.add(new Komunikacia(id++, getSrcIpArp(packet), getDstIpArp(packet), 0, 0, 0, true, false));
			komunikacie.get(komunikacie.size() - 1).addToPacketList(packet);
		}
		else if (typ == 2) {
			for (Komunikacia k: komunikacie) {
				
				if (!k.hasEnd()) {
					String src = getSrcIpArp(k.getPacketList().get(0));
					String dst = getDstIpArp(k.getPacketList().get(0));
					String srcA = getSrcIpArp(packet);
					String dstA = getDstIpArp(packet);
					
					if (src.equals(dstA) && dst.equals(srcA)) {
						k.addToPacketList(packet);
						k.setEnd(true);
						break;
					}
				}
			}
		}
	}
	
	private static void kontrolaICMP() {
		
		for (Komunikacia k: komunikacie) {
			for (JPacket p: k.getPacketList()) {
				int type = p.getUByte(34);
				int code = p.getUByte(35);
				
				if (type == 0 && code == 0) {
					k.setEnd(true);
					break;
				}
			}
		}
	}
	
	private static int getPortNumberFromFile(String string) {
		int port_n = -1;
		Path file = FileSystems.getDefault().getPath("C:\\Users\\Martin\\git\\pks_zadanie1\\PKS_ZADANIE_1\\bin\\files", "tcp_port_number.txt");
		
		try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
		    String line = null;
		    while ((line = reader.readLine()) != null) {
		    	String[] riadok = line.split(",");
		    	if (riadok[1].toLowerCase().contains(string.toLowerCase())) {
		    		port_n = Integer.parseInt(riadok[0]);
		    		Gui.vypis("Zhoda v subore: " + line + "\n");
		    		Gui.vypis("Vyhladavanie komunikacie cez port: " + riadok[0] + "\n\n");
		    		break;                                                                                                 
		    	}
		    }
		} 
		catch (Exception e) {
		    Gui.vypis("Chyba pri citani suboru: " + e + "\n");
		}
		
		return port_n;
	}

	private static int wireSize(JPacket p) {
		int size = p.getCaptureHeader().wirelen();
		return (size > 60)? size + 4: 64;
	}
	
	public static int[] getFlags(JPacket packet) {
		int flags[] = {0, 0, 0, 0};
		int val = packet.getUByte(47);
		
		flags[0] = ((val & (1 << 4)) != 0)? 1: 0; 
		flags[1] = ((val & (1 << 2)) != 0)? 1: 0;
		flags[2] = ((val & (1 << 1)) != 0)? 1: 0;
		flags[3] = ((val & (1 << 0)) != 0)? 1: 0;
		
		return flags;
	}
	
	private static void vypisPacket(JPacket p) {
		Gui.vypis("No:              " + p.getFrameNumber() + "\n");
		Gui.vypis("Zachytena dlzka: " + p.getCaptureHeader().caplen() + "\n");
		Gui.vypis("Dlzka po mediu:  " + wireSize(p) + "\n");
		Gui.vypis("Typ:             " + typ(p) + "\n");
		Gui.vypis("Source MAC:      " + srcMac(p) + "\n");
		Gui.vypis("Destination MAC: " + dstMac(p) + "\n");
		Gui.vypis("Src Port: " + getSrcPort(p) + "\n");
		Gui.vypis("Dst Port: " + getDstPort(p) + "\n");
		int flags[] = getFlags(p);
		Gui.vypis("Flags\n");
		Gui.vypis("ACK: " + flags[0] + "\n");
		Gui.vypis("RST: " + flags[1] + "\n");
		Gui.vypis("SYN: " + flags[2] + "\n");
		Gui.vypis("FIN: " + flags[3] + "\n");
		Gui.vypis(hexPacket(p) + "\n\n");
	}
	
	private static void vypisArpPacket(JPacket p) {
		Gui.vypis("No:              " + p.getFrameNumber() + "\n");
		Gui.vypis("Zachytena dlzka: " + p.getCaptureHeader().caplen() + "\n");
		Gui.vypis("Dlzka po mediu:  " + wireSize(p) + "\n");
		Gui.vypis("Typ:             " + ((p.getUShort(20) == 1)? ("ARP Request\nIP: " + getDstIpArp(p) + " MAC: ???\n"): ("ARP Reply\nIP: " + getDstIpArp(p) + " MAC: " + srcMac(p)) + "\n"));
		Gui.vypis("Source IP:       " + getSrcIpArp(p) + "\n");
		Gui.vypis("Destination IP:  " + getDstIpArp(p) + "\n");
		Gui.vypis("Source MAC:      " + srcMac(p) + "\n");
		Gui.vypis("Destination MAC: " + dstMac(p) + "\n");
		Gui.vypis(hexPacket(p) + "\n\n");
	}
	
	private static void vypisIcmpPacket(JPacket p) {
		Gui.vypis("No:              " + p.getFrameNumber() + "\n");
		Gui.vypis("Zachytena dlzka: " + p.getCaptureHeader().caplen() + "\n");
		Gui.vypis("Dlzka po mediu:  " + wireSize(p) + "\n");
		Gui.vypis("Typ:             " + typ(p) + "\n");
		Gui.vypis("Source MAC:      " + srcMac(p) + "\n");
		Gui.vypis("Destination MAC: " + dstMac(p) + "\n");
		Gui.vypis("Typ ICMP:        " + getIcmpType(p) + "\n");
		Gui.vypis("Kod ICMP:        " + getIcmpCode(p) + "\n");
		Gui.vypis(hexPacket(p) + "\n\n");
	}
	
	private static void vypisTftpPacket(JPacket p) {
		Gui.vypis("No:              " + p.getFrameNumber() + "\n");
		Gui.vypis("Zachytena dlzka: " + p.getCaptureHeader().caplen() + "\n");
		Gui.vypis("Dlzka po mediu:  " + wireSize(p) + "\n");
		Gui.vypis("Typ:             " + typ(p) + "\n");
		Gui.vypis("Source MAC:      " + srcMac(p) + "\n");
		Gui.vypis("Destination MAC: " + dstMac(p) + "\n");
		Gui.vypis("Typ TFTP:        " + getTftpType(p) + "\n");
		Gui.vypis(hexPacket(p) + "\n\n");
	}
	
	private static void vypisArpKom() {
		for (Komunikacia k: komunikacie) {
			if (k.hasStart() && k.hasEnd()) {
				Gui.vypis("Komunikacia c. " + k.getId() + "\n");
				Gui.vypis(((k.hasStart() && k.hasEnd())? "Kompletna\n": "Nekompletna\n"));
				for (int i = 0; i < k.getPacketList().size(); ++i)
					vypisArpPacket(k.getPacketList().get(i));
			}
		}
	}
	
	private static void vypisTftpKom() {
		Gui.vypis("zoznam tftp\n");
		for (Tftp k: tftp) {
		//	if (k.hasStart() && k.hasEnd()) {
				Gui.vypis("Komunikacia c. " + k.getId() + "\n");
				Gui.vypis(((k.hasStart() && k.hasEnd())? "Kompletna\n": "Nekompletna\n"));
				for (int i = 0; i < k.getPacketList().size(); ++i)
					vypisTftpPacket(k.getPacketList().get(i));
		//	}
		}
	}
	
	private static void vypisIcmpKom() {
		for (Komunikacia k: komunikacie) {
			Gui.vypis("Komunikacia c. " + k.getId() + "\n");
			Gui.vypis(((k.hasStart() && k.hasEnd())? "Kompletna\n": "Nekompletna\n"));
			for (int i = 0; i < k.getPacketList().size(); ++i)
				vypisIcmpPacket(k.getPacketList().get(i));
		}
		
	}
	
	private static String getIcmpType(JPacket p) {
		Path file = FileSystems.getDefault().getPath("C:\\Users\\Martin\\git\\pks_zadanie1\\PKS_ZADANIE_1\\bin\\files", "icmp_type.txt");
		int type = p.getUByte(34);
		
		try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
		    String line = null;
		    while ((line = reader.readLine()) != null) {
		    	String[] riadok = line.split(",");
		    	if (Integer.parseInt(riadok[0]) == type) {
		    		return riadok[1];
		    	}
		    }
		} 
		catch (Exception e) {
		    Gui.vypis("Chyba pri citani suboru: " + e + "\n");
		}
		
		return String.format("Neznamy (%d)", type);
	}
	
	private static String getTftpType(JPacket p) {
		Path file = FileSystems.getDefault().getPath("C:\\Users\\Martin\\git\\pks_zadanie1\\PKS_ZADANIE_1\\bin\\files", "tftp_type.txt");
		int type = p.getUShort(42);
		
		try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
		    String line = null;
		    while ((line = reader.readLine()) != null) {
		    	String[] riadok = line.split(",");
		    	if (Integer.parseInt(riadok[0]) == type) {
		    		return riadok[1];
		    	}
		    }
		} 
		catch (Exception e) {
		    Gui.vypis("Chyba pri citani suboru: " + e + "\n");
		}
		
		return String.format("Neznamy (%d)", type);
	}
	
	private static String getIcmpCode(JPacket p) {
		int type = p.getUByte(34);
		int code = p.getUByte(35);
		
		if (type == 3) {
			Path file = FileSystems.getDefault().getPath("C:\\Users\\Martin\\git\\pks_zadanie1\\PKS_ZADANIE_1\\bin\\files", "icmp_dest_code.txt");
			
			try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
			    String line = null;
			    while ((line = reader.readLine()) != null) {
			    	String[] riadok = line.split(",");
			    	if (Integer.parseInt(riadok[0]) == code) {
			    		return riadok[1];
			    	}
			    }
			} 
			catch (Exception e) {
			    Gui.vypis("Chyba pri citani suboru: " + e + "\n");
			}
			
			return String.format("Neznamy (%d)", code);
		}
		else
			return String.format("Neznamy (%d)", code);
		
		
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
				Gui.vypis("Velkosti ramcov:\n");
				vypisPacketSizeStat(k);
				
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
					break;
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
				vypisPacketSizeStat(k);
				
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
					break;
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

	private static boolean addPacketToComm(String source, String destination, int srcPort, int dstPort, JPacket packet) {
		for (Komunikacia k: komunikacie) {
			if (( (source.equals(k.getSource()) && destination.equals(k.getDestination()))   || 
				  (source.equals(k.getDestination()) && destination.equals(k.getSource())) ) &&
				( (srcPort == k.getPortSrc() && dstPort == k.getPortDst())			 ||
				  (dstPort == k.getPortSrc() && srcPort == k.getPortDst()) )		 &&
				  (k.hasEnd() == false) ) {
				k.addToPacketList(packet);
				k.updateSizeList(wireSize(packet));
				return true;
			}	
		}
		
		return false;
	}
	
	private static boolean addTftpPacket(String source, String destination, int srcPort, int dstPort, JPacket packet) {
		//System.out.println("Porovnavam\n");
		//System.out.println(String.format("src: %s\ndst: %s\nsrcP: %d, dstP: %d\nno: %d\n", source, destination, srcPort, dstPort, tftp.size()));
		
		for (Tftp k: tftp) {
			//System.out.println(String.format("inside cycle\nsrc: %s\ndst: %s\nsrcP: %d, dstP: %d\n", k.getSource(), k.getDestination(), k.getPortSrc(), k.getPortDst()));
			if (k.getPortDst() == -1) {
				if (( (source.equals(k.getSource()) && destination.equals(k.getDestination()))   || 
					  (source.equals(k.getDestination()) && destination.equals(k.getSource())) ) &&
					( (srcPort == k.getPortSrc() )		||
					  (dstPort == k.getPortSrc()) )		&&
					  (k.hasEnd() == false) ) {
					k.addToPacketList(packet);
					k.updateSizeList(wireSize(packet));
					k.setPortDst(srcPort);
					return true;
				}	
			}
			else {
				if (( (source.equals(k.getSource()) && destination.equals(k.getDestination()))   || 
						  (source.equals(k.getDestination()) && destination.equals(k.getSource())) ) &&
						( (srcPort == k.getPortSrc() && dstPort == k.getPortDst())			 ||
						  (dstPort == k.getPortSrc() && srcPort == k.getPortDst()) )		 &&
						  (k.hasEnd() == false) ) {
						k.addToPacketList(packet);
						k.updateSizeList(wireSize(packet));
						return true;
				}
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
	
	private static String getSrcIpArp(JPacket packet) {
		return new String(String.format("%d.%d.%d.%d", packet.getUByte(28), packet.getUByte(29), packet.getUByte(30), packet.getUByte(31)));
	}
	
	private static String getDstIpArp(JPacket packet) {
		return new String(String.format("%d.%d.%d.%d", packet.getUByte(38), packet.getUByte(39), packet.getUByte(40), packet.getUByte(41)));
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
	
	public static void vymazZoznamTftp() {
		while (tftp.size() > 0)
			tftp.remove(tftp.size() - 1);
		
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
	
	public static void vypisPacketSizeStat(Komunikacia k) {
		Gui.vypis("<   0 -   19> : " + k.getSizeListItem(0) + "\n");
		Gui.vypis("<  20 -   39> : " + k.getSizeListItem(1) + "\n");
		Gui.vypis("<  40 -   79> : " + k.getSizeListItem(2) + "\n");
		Gui.vypis("<  80 -  159> : " + k.getSizeListItem(3) + "\n");
		Gui.vypis("< 160 -  319> : " + k.getSizeListItem(4) + "\n");
		Gui.vypis("< 320 -  639> : " + k.getSizeListItem(5) + "\n");
		Gui.vypis("< 640 - 1279> : " + k.getSizeListItem(6) + "\n");
		Gui.vypis("<1280 -     > : " + k.getSizeListItem(7) + "\n");
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
