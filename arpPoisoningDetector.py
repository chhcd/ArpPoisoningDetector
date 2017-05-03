#! /usr/bin/env python
from scapy.all import *

THRESHOLD = 12
packets = {}
victim_ip = None
mac_victim = None
attacker_mac = None
flag = False
format_answer = "\n"

def wait_for_answer(packet):
    global format_answer
    print('\n')
    format_answer += ("MAC of victim: " + packet.hwsrc + '\n')
    print(format_answer)
    exit()

def buildPacket(ip):
    mypacket = Ether()/ARP()
    mypacket.op = 1 #request
    mypacket.psrc="10.12.161.84" #IP OF HOST/DETECTOR
    mypacket.hwdst="ff:ff:ff:ff:ff:ff" # all victims
    mypacket.pdst = ip # IP OF VICTIMA
    mypacket.dst = "ff:ff:ff:ff:ff:ff" # all victims
    return mypacket

def check_for_and_add(packet, key):
    try:
        packet[key] += 1
    except:
        packet[key] = 1

def arp_traffic(packet):
    if ARP in pkt and packet[ARP].op == 2: #is-at
        key = packet[ARP].hwsrc +  packet[ARP].psrc
        check_for_and_add(packets, key)

        if flag and packet[ARP].psrc == victim_ip and packet[ARP].hwsrc != attacker_mac:
            wait_for_answer(packet[ARP])

        if packets[key] >= THRESHOLD:
            global flag
            flag = True
            global format_answer
            format_answer = ("Attacker\'s MAC: " + packet[ARP].hwsrc + '\n' + "Victim\'s IP: " + packet[ARP].psrc + '\n')
            global victim_ip
            global attacker_mac
            attacker_mac = packet[ARP].hwsrc
            victim_ip = packet[ARP].psrc
            arp_request_packet = buildPacket(packet[ARP].psrc)
            sendp(arp_request_packet)
            print('\n' + "ARP POISONING! " + '\n' + "IP of victim -> " + victim_ip + '\n' + "MAC of attacker -> " + attacker_mac)

print("Monitoring network for ARP Poisoning Attacks...")
sniff(prn=arp_traffic, filter="arp", store=0)