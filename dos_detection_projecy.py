import scapy.all as scapy
import argparse
from collections import defaultdict
import time

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='Network interface to monitor', required=True)
    parser.add_argument('-t', '--threshold', dest='threshold', type=int, help='Threshold for requests per second', default=100)
    parser.add_argument('-d', '--duration', dest='duration', type=int, help='Duration to monitor (seconds)', default=60)
    options = parser.parse_args()
    return options

def detect_dos(interface, threshold, duration):
    ip_counter = defaultdict(int)
    start_time = time.time()

    def process_packet(packet):
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP].src
            ip_counter[ip] += 1

    scapy.sniff(iface=interface, store=False, prn=process_packet, timeout=duration)
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print(f"\nMonitoring completed. Duration: {elapsed_time:.2f} seconds")
    
    for ip, count in ip_counter.items():
        if count / elapsed_time > threshold:
            print(f"DoS attack detected from IP: {ip} - Requests per second: {count / elapsed_time:.2f}")

if __name__ == '__main__':
    options = get_arguments()
    print(f"Monitoring on interface {options.interface} for {options.duration} seconds...")
    detect_dos(options.interface, options.threshold, options.duration)
