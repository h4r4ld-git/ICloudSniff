import pyshark

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