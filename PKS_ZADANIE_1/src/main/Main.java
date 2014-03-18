package main;

import gui.Gui;

public class Main {

	public static void main(String[] args) {
		Gui.gui();
	}

}


/*			Uloha:										pcap subor
 * 
 *	a) HTTP komunikácie						 			1, 3, 4, 6, 8, 9, 10, 11, 12, 14, 20, 21, 24, 25
 *	b) HTTPS komunikácie 								8, 10, 12, 14, 17
 *	c) TELNET komunikácie 								9, 14, 19
 *	d) SSH komunikácie									18
 *	e) FTP riadiace komunikácie (21)					6, 7, 8, 12, 13, 14, 16						
 *	f) FTP dátové komunikácie (20)						6, 7, 8, 12, 13, 14, 16
 *	g) Všetky TFTP komunikácie							15
 *	h) Všetky ICMP komunikácie							6, 15, (22, 24, 25 v6)
 *	i) Všetky ARP dvojice (request – reply)				1, 2, 8, 10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 25
 */
