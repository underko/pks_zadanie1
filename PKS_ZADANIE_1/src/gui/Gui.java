package gui;

import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.text.*;

import code.Analyzator;
import code.Filter;

@SuppressWarnings("serial")
public class Gui extends JFrame {
	
	static private JFrame win;
	static private JButton btn_anlz, btn_load, btn_clr;
	static private JTextPane textpane;
	static private JScrollPane sBar;
	static private JComboBox<String> cmbVyber;
	
	static StyledDocument poleDoc;
	
	final private static Font font = new Font("Courier", Font.PLAIN, 12);
	final private static Font font_btn = new Font("Arial", Font.BOLD, 11);
	final private static Border obrys= BorderFactory.createLineBorder(Color.black);
	
	final static File dir = new File("D:\\skola\\3.rocnik\\PKS\\1.zadanie 2014");
	final static JFileChooser fc = new JFileChooser(dir);
	final static String[] cmbFill = {	"Výber podúlohy",
										"-----------------------------------------", 
										"a) HTTP komunikácie", 
										"b) HTTPS komunikácie", 
										"c) TELNET komunikácie", 
										"d) SSH komunikácie", 
										"e) FTP riadiace komunikácie", 
										"f) FTP dátové komunikácie", 
										"g) Všetky TFTP komunikácie", 
										"h) Všetky ICMP komunikácie", 
										"i) Všetky ARP dvojice (request – reply)"};
	
	public static void gui() {
		
		win = new JFrame("PKS Packet Analyzer");
		win.setLayout(null);
		win.setSize(800, 600);
		win.setVisible(true);
		win.setResizable(false);
		win.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		win.setLocationRelativeTo(null);
		
		//btn_anlz
		btn_anlz = new JButton("Analyzuj");
		btn_anlz.setBounds(win.getWidth() / 2 + 10, 5, 80, 30);
		btn_anlz.setFont(font_btn);
		btn_anlz.setContentAreaFilled(false);
		win.add(btn_anlz);
		
		//btn_load
		btn_load = new JButton("Load");
		btn_load.setBounds(win.getWidth() / 2 + 10 + 80 + 5, 5, 80, 30);
		btn_load.setFont(font_btn);
		btn_load.setContentAreaFilled(false);
		win.add(btn_load);
		
		//btn_clr
		btn_clr = new JButton("Clear");
		btn_clr.setBounds(win.getWidth() / 2 + 10 + 80 + 5 + 80 + 5, 5, 80, 30);
		btn_clr.setFont(font_btn);
		btn_clr.setContentAreaFilled(false);
		win.add(btn_clr);
				
		//pole na vypis
		textpane = new JTextPane();
		poleDoc = textpane.getStyledDocument();
		
		sBar = new JScrollPane(textpane);
		sBar.setBounds(5, 5, win.getWidth() / 2, win.getHeight() - 35);
		sBar.setBorder(obrys);
		textpane.setEditable(false);
		textpane.setFont(font);
		win.add(sBar);
		
		//cmb vyberu ulohy
		cmbVyber = new JComboBox<String>(cmbFill);
		cmbVyber.setBounds(win.getWidth() / 2 + 10, 40, 250, 20);
		cmbVyber.setFont(font);
		win.add(cmbVyber);

		obnov();
		
		//action listenery
		btn_anlz.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				//spustenie analyzatora
				int index = cmbVyber.getSelectedIndex();
				
				if (index == 0 || index == 1) {		//zakladny analyzator 1.uloha
					try {
						Analyzator.analyza();
						vypis("Vsetko ok\n");
					} catch (Exception e) {
						vypis("Chyba: " + e + "\n");
					}
				}
				else {								//analyzator komunikacii 3.uloha
					try {
						Analyzator.komunikacie(index);
						vypis("Vsetko ok\n");
					} catch (Exception e) {
						vypis("Chyba: " + e + "\n");
					}
				}
			}
		});
		
		btn_load.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				fc.setAcceptAllFileFilterUsed(false);
				fc.setFileFilter(new Filter(".pcap", "Vzorky na analyzu typu PCAP"));
				int ret_val = fc.showOpenDialog(win);
				
				if (ret_val == JFileChooser.APPROVE_OPTION) {
		            File file = fc.getSelectedFile();
		            
		            vypis("Vybrany subor: " + file.getName() + "\n");
		            vypis("subor: " + fc.getSelectedFile() + "\n");
		            
		            Analyzator.setSubor(fc.getSelectedFile());
		        }
			}
		});
		
		btn_clr.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				textpane.setText("");
				Analyzator.vymazZoznamIp();
				Analyzator.vymazZoznamTftp();
				Analyzator.vymazZoznamKom();
			}
		});
	}
	
	public static String getCmbText(int index) {
		return cmbVyber.getItemAt(index);
	}
	
	public static void vypis(String s) {
		try {
			poleDoc.insertString(poleDoc.getLength(), s, null);
			textpane.setCaretPosition(textpane.getDocument().getLength());
		} 
		catch (BadLocationException e) {
			e.printStackTrace();
		}
	}
	
	public static void obnov() {
		try {
			win.revalidate();
			win.repaint();
		}
		catch (Exception e) {
			// to je zle :D
		}
	}
	
}
