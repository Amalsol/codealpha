from scapy.all import sniff, ARP, IP, TCP
import logging

logging.basicConfig(filename='network_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):
    try:
        log_message = ""
        if packet.haslayer(ARP):
            arp_packet = packet[ARP]
            log_message = f"ARP Packet: {arp_packet.summary()}"
        elif packet.haslayer(IP):
            ip_packet = packet[IP]
            log_message = f"IP Packet: {ip_packet.summary()}"
        elif packet.haslayer(TCP):
            tcp_packet = packet[TCP]
            log_message = f"TCP Packet: {tcp_packet.summary()}"
        
        if log_message:
            logging.info(log_message)  # Log to file

    except Exception as e:
        error_message = f"Error processing packet: {e}"
        logging.error(error_message)

def start_sniffing(interface):
    try:
        logging.info(f"Sniffing on interface {interface}...")
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        error_message = f"Error starting sniffing: {e}"
        logging.error(error_message)

if __name__ == "__main__":

    start_sniffing('eth0')

