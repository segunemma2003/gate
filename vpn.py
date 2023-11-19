import socket
import scapy.all as scapy
import threading

def capture_traffic():
    while True:
        packets = scapy.sniff(filter="tcp and dst port 80 or dst port 443", iface="eth0")
        for packet in packets:
            if packet.haslayer(scapy.DNSQR):
                source_ip = packet[scapy.IP].src
                query_name = packet[scapy.DNSQR].qname.decode("utf-8")

                print(f"[INFO] {source_ip} is attempting to browse: {query_name}")

def start_capture():
    capture_thread = threading.Thread(target=capture_traffic)
    capture_thread.start()

def main():
    start_capture()

if __name__ == "__main__":
    main()