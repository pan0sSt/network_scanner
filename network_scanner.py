#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) # ARP object creation, asks who has target IP
    broadcast   = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Ethernet object creation, set destination MAC to broadcast MAC
    arp_request_broadcast = broadcast/arp_request # Combine into a single packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Send packets with custom Ether, send packet and receive response. "timeout": Time to wait for response

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n----------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)