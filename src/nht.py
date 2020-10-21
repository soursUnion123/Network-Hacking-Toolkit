import nht_netcat
import nht_ip_scanner
import nht_arp_poison

def main():
    print "************Welcome to Network Hacking Tools**************"
    print ""
    print "Select number that you want to do!"
    print "After,Tell you the best way to execute each Tools"
    print ""
    print "(1)  Similar Netcat"
    print "(2)  Local IP Address Scanner"
    print "(3)  ARP Poisoning Attack"
    main_num = input(">>")

    if (main_num == 1):
        print "====== Similar Netcat ======="
        print ""
        nht_netcat.netcat()
    if (main_num == 2):
        print "====== Local IP Address Scanner ======="
        print ""
        nht_ip_scanner.scan()
    if (main_num == 3):
        print "====== ARP Poisoning Attack ======"
        print ""
        nht_arp_poison.arp_poisoning()


main()
