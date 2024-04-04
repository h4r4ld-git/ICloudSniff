import pyshark
import time

<<<<<<< HEAD
cap = pyshark.FileCapture('linux-firefox.pcapng')

dns = {}
dest = []
for packet in cap:
    # Partie destinataires
    if "ip" in dir(packet) and packet.ip.dst not in dest:
        dest.append(packet.ip.dst)
    if "ipv6" in dir(packet) and packet.ipv6.dst not in dest:
        dest.append(packet.ipv6.dst)
    
    # Partie DNS
    if "dns" in dir(packet):
        if "resp_name" in dir(packet.dns):
            if packet.dns.resp_name not in dns:
                if "aaaa" in dir(packet.dns):
                    dns[packet.dns.aaaa] = packet.dns.resp_name
                if "a" in dir(packet.dns):
                    dns[packet.dns.a] = packet.dns.resp_name
print("Destinataires\n")
for d in dest:
    if d in dns.keys():
        print(f"\t{d}\t{dns[d]}")


for funct in ["Collab-file-linux.pcapng", "DNS_Connection_Opera.pcapng", "download-upload-linux.pcapng"]: 
    cap = pyshark.FileCapture(funct)
    s = 0
    t = 0
    for packet in cap:
        s += int(packet.frame_info.len)*8
        t = packet.frame_info.time_relative
    print(funct, s, t)
=======
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
>>>>>>> f1064762f9d455dc94e32c06a7ed28c966d01c66
