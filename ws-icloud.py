import pyshark

cap = pyshark.FileCapture('linux-firefox.pcapng')
dns = {}
for packet in cap:
    if "dns" in dir(packet):
        if "resp_name" in dir(packet.dns):
            if packet.dns.resp_name not in dns:
                if "aaaa" in dir(packet.dns):
                    dns[packet.dns.aaaa] = packet.dns.resp_name
                if "a" in dir(packet.dns):
                    dns[packet.dns.a] = packet.dns.resp_name
print(dns)