package main;

import gui.Gui;

public class Main {

	public static void main(String[] args) {
		Gui.gui();
	}

}


/*			Uloha:										pcap subor
 * 
 *	a) HTTP komunik�cie						 			1, 3, 4, 6, 8, 9, 10, 11, 12, 14, 20, 21, 24, 25
 *	b) HTTPS komunik�cie 								8, 10, 12, 14, 17
 *	c) TELNET komunik�cie 								9, 14, 19
 *	d) SSH komunik�cie									18
 *	e) FTP riadiace komunik�cie (21)					6, 7, 8, 12, 13, 14, 16						
 *	f) FTP d�tov� komunik�cie (20)						6, 7, 8, 12, 13, 14, 16
 *	g) V�etky TFTP komunik�cie							15
 *	h) V�etky ICMP komunik�cie							6, 15, (22, 24, 25 v6)
 *	i) V�etky ARP dvojice (request � reply)				1, 2, 8, 10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 25
 */
