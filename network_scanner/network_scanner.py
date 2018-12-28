import scapy.all as scapy
import argparse  # optparse is deprecated


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range")
    options = parser.parse_args()  # argumentparser does not return arguments
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # Adress Resolution Protocol / pdst stands for IPField
    # print(arp_request.summary()) to print the summary
        # prints out "ARP who has <ipfield> says <ip>  -> which is the ip to send back to"
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet frame / dst stands for DestMacField
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # [0] returns the answered list


    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    # use scapy.ls(scapy.?()) to check documentations
        # e.g. scapy.ls(scapy.ARP()) to read the fields and variables

    return clients_list


def print_results(result_list):
    print("IP\t\t\tMAC ADDRESS")
    print('----------------------------------------------------------------')
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_results = scan(options.target)  # "10.0.2.1/24"
print_results(scan_results)
