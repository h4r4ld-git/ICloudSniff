import pyshark
import time

def analyze_packets(file_name):
    cap = pyshark.FileCapture(file_name)
    total_size = 0
    packet_count = 0
    dns = {}
    print("Analyzing packets...")
    start_time = None  # Initialize start time

    for packet in cap:
        if "dns" in dir(packet):
            if "resp_name" in dir(packet.dns):
                if packet.dns.resp_name not in dns:
                    if "aaaa" in dir(packet.dns):
                        dns[packet.dns.aaaa] = packet.dns.resp_name
                    if "a" in dir(packet.dns):
                        dns[packet.dns.a] = packet.dns.resp_name

        # Record the start time with the first packet
        if start_time is None:
            start_time = float(packet.sniff_time.timestamp())

        elapsed_time = float(packet.sniff_time.timestamp()) - start_time

        # Stop counting total_size and packet_count after 1 minute
        if elapsed_time <= 60:
            total_size += int(packet.length)
            packet_count += 1

    print(dns)
    print(f"Total data exchanged in the first minute: {total_size} bytes")
    print(f"Average packet size in the first minute: {total_size/packet_count} bytes")
    cap.close()

# Call the function with the pcapng file
analyze_packets('linux-firefox.pcapng')