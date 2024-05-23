#!/usr/bin/env python3
import random
from typing import Tuple
from threading import Thread
from scapy.packet import Packet
from scapy.sendrecv import send, sniff
from scapy.layers.inet import TCP, IP, Ether, ICMP, UDP
from scapy.layers.http import HTTP
from ipaddress import IPv4Interface, ip_network, ip_address
import socket
import os
import time
import datetime
# from hwcounter import Timer

PRIVATE_IFACE = "r1-eth1"
PRIVATE_IP = "10.0.0.1"
PRIVATE_IP_subnet = "10.0.0.0/24"

PUBLIC_IFACE = "r1-eth2"
PUBLIC_IP = "192.168.1.1"

# Use "icmp" to test icmp only
# Use "tcp port 80" to test tcp only
# FILTER = "icmp or tcp port 80"
FILTER = "udp"

def print(*args):
    with open("logs/nat_log.txt", "a") as f:
        for arg in args:
            f.write(str(arg) + " ")
        f.write("\n")


class NATTable:

    def __init__(self):
    # NAT translation table ... DONE
    # = WORK HERE = ... DONE
    # IMPLEMENT THIS ... DONE
        self.data = {}
        self.prev_port = 5000
    
    def _random_id(self):
        # Return Next Available Port Number
        if self.prev_port == 65535:
            raise Exception("NAT Table Full")
        self.prev_port += 1
        return self.prev_port
        # return random.randint(30001, 65535)

    def print_mappings(self):
        with open("logs/nat_mappings.txt", "w") as f:
            now = datetime.datetime.now()
            f.write("Last Updated: "+ str(now) +"\n")
            f.write("No of mappings:" + str(len(self.data)) + "\n")
            bound_line = "-"*72
            line = "|{:^15} | {:^15} | {:^15} | {:^15} |".format("LAN IP", "LAN PORT", "WAN IP", "WAN PORT")
            f.write(bound_line + "\n")
            f.write(line + "\n")
            f.write(bound_line + "\n")
            for key, value in self.data.items():
                line = "|{:^15} | {:^15} | {:^15} | {:^15} |".format(value[0], value[1], key[0], key[1])
                # f.write(bound_line + "\n")
                f.write(line + "\n")
                f.write(bound_line + "\n")



    def set(self, ip_src, id_src) -> Tuple[str, int]:
        new_ip_src = PUBLIC_IP #this is the WAN connection so it should be public so everyone will see it

        wanList = list(self.data.keys())
        lanList = list(self.data.values())

        lan_tup = (ip_src, id_src) ##create a dummy tuple to see if its in the list of lanAddresses and Ports
        if lan_tup in lanList:
            i = lanList.index(lan_tup)        #Get index of the tuple location 
            new_id_src =wanList[i][1]   #retrieve corresponding wan port number and set it as the port number for same key/value
        else:
            new_id_src = self._random_id()  #if not found, just make a random port number
        
        wan_tup = (new_ip_src, new_id_src)


        self.data.update({wan_tup: lan_tup}) #Append the whole thing in one big dictionary

        return new_ip_src, new_id_src


    def get(self, ip_dst, id_dst) -> Tuple[str, int]:
        key_tuple = (ip_dst, id_dst)
        
        if key_tuple in self.data:
            return self.data[key_tuple]
        return None 


icmp_mapping = NATTable()
tcp_udp_mapping = NATTable()

def process_pkt_private(pkt: Packet):
    try:
        # with Timer() as t:
            # type_of_operation = "New Entry"
        if True:
            # print("Source:", pkt[IP].src, "Destination:", pkt[IP].dst)
            # Reference: https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python
            if ip_address(pkt[IP].src) not in ip_network(PRIVATE_IP_subnet):
                return # we sniffed a packet we are sending to the subnet, ignore


            if ip_address(pkt[IP].src) == ip_address(PRIVATE_IP):
                # print("We sniffed a packet we are sending")
                return

            print("received pkt from private interface", pkt.sniffed_on, pkt.summary())
            #incoming
            #if its outgoing, use NAT Table
            pkt[Ether].src      # accessing a field in the Ether Layer, not necessary for this lab

            # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L502
            pkt[IP].src         # accessing a field in the IP Layer

            try:
                # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L874
                pkt[ICMP].id    # accessing a field in the ICMP Layer, will fail in a TCP packet
            
                # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L678
                pkt[TCP].sport  # accessing a field in the TCP Layer, will fail in a ICMP packet
            except:
                pass

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # https://scapy.readthedocs.io/en/latest/usage.html#stacking-layers
            # Stack a new packet like so
            # IP(src="xxx.xxx.xxx.xxx", dst="xxx.xxx.xxx.xxx", ttl=???) / ptk[TCP or ICMP, depends on pkt]
            # if its outgoing, look at the two things below
            if ICMP in pkt:
                print('\tICMP Packet captured on private interface')
                
                src_id = pkt[ICMP].id
                
                # Add it into icmp_mapping, if it doesn't already exist
                # remember: icmp does not handle ports
                pub_ip, pub_id = icmp_mapping.set(src_ip, src_id)

                # Make new packet by updating Network Layer header, using public IP, public src (the ICMP id), and info from pkt
                pkt[ICMP].id = pub_id
                icmp_header = ICMP(id=pub_id, code=0, type=8)
                new_pkt = IP(src=pub_ip, dst=dst_ip) / icmp_header
            elif TCP in pkt:
                print('\tTCP Packet captured on private interface')
                
                src_port = pkt[TCP].sport

                # remember: TCP does handle ports

                # Add it into icmp_mapping, if it doesn't already exist
                pub_ip, pub_sport = tcp_udp_mapping.set(src_ip, src_port)

                # UNDERSTAND: don't worry about internal, sending only private packets to public packets
                # NEW TCP HEADER PASS SRC PORT AND DST PORT
                # SAVE MESSAGE
                # CAPTURE ANY APPLICATION LAYER PACKETS
                dst_port = pkt[TCP].dport
                tcp_header = TCP(sport=pub_sport, dport=dst_port) # transport layer header

                new_pkt = IP(src=pub_ip, dst=dst_ip) / tcp_header / pkt[TCP].payload
                print("T: ", pkt.show())
            elif UDP in pkt:
                print('\tUDP Packet captured on private interface')
                src_port = pkt[UDP].sport

                pub_ip, pub_sport = tcp_udp_mapping.set(src_ip, src_port)

                print("UDP Mapping: ", pub_ip, pub_sport)

                dst_port = pkt[UDP].dport
                udp_header = UDP(sport=pub_sport, dport=dst_port) # transport layer header

                new_pkt = IP(src=pub_ip, dst=dst_ip) / udp_header / pkt[UDP].payload


            # create a new pkt depending on what is being requested
            # keep track of new and current connections inside a data structure

            # make sure to send new packet to the correct network interface
            send(new_pkt, iface=PUBLIC_IFACE, verbose=False)
        # with open("naive_cycles.txt", "a") as f:
            # f.write(str(t.cycles) + "\n")
    except Exception as e:
        print("ERROR: ", e)

def process_pkt_public(pkt: Packet):
    try:
        if pkt[IP].src == PUBLIC_IP:
            return # skip unecessary packets
        print("received pkt from public interface", pkt.sniffed_on, pkt.summary())
        #incoming
        #if its outgoing, use NAT Table
        pkt[Ether].src      # accessing a field in the Ether Layer, not necessary for this lab

        # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L502
        pkt[IP].src         # accessing a field in the IP Layer

        try:
            # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L874
            pkt[ICMP].id    # accessing a field in the ICMP Layer, will fail in a TCP packet
        
            # https://github.com/secdev/scapy/blob/v2.4.5/scapy/layers/inet.py#L678
            pkt[TCP].sport  # accessing a field in the TCP Layer, will fail in a ICMP packet
        except:
            pass
        
        dst_ip = pkt[IP].dst
        src_ip = pkt[IP].src

        # https://scapy.readthedocs.io/en/latest/usage.html#stacking-layers
        # Stack a new packet like so
        # IP(src="xxx.xxx.xxx.xxx", dst="xxx.xxx.xxx.xxx", ttl=???) / ptk[TCP or ICMP, depends on pkt]
        # if its outgoing, look at the two things below
        if ICMP in pkt:
            print('\tICMP Packet captured on public interface')
            
            id = pkt[ICMP].id

            # Add it into icmp_mapping, if it doesn't already exist
            # remember: icmp does not handle ports
            private_mapping = icmp_mapping.get(dst_ip, id)
            if private_mapping is None:
                return
            else:
                priv_ip, priv_id = private_mapping

            # Make new packet by updating Network Layer header, using public IP, public src (the ICMP id), and info from pkt
            pkt[ICMP].id = priv_id
            new_pkt = IP(src=src_ip, dst=priv_ip) / pkt[ICMP]

        elif TCP in pkt:
            print('\tTCP Packet captured on private interface')

            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            # Add it into icmp_mapping, if it doesn't already exist

            private_mapping = cp_mapping.get(dst_ip, dst_port)
            if private_mapping is None:
                return
            else:
                priv_ip, priv_sport = private_mapping

            # UNDERSTAND: don't worry about internal, sending only private packets to public packets
            # NEW TCP HEADER PASS SRC PORT AND DST PORT
            # SAVE MESSAGE
            # CAPTURE ANY APPLICATION LAYER PACKETS
            tcp_header = TCP(sport=src_port, dport=priv_sport) # transport layer header


            new_pkt = IP(src=src_ip, dst=priv_ip) / tcp_header / pkt[TCP].payload
        elif UDP in pkt:
            print('\tUDP Packet captured on private interface')

            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            private_mapping = tcp_udp_mapping.get(dst_ip, dst_port)
            if private_mapping is None:
                return
            else:
                priv_ip, priv_sport = private_mapping

            udp_header = UDP(sport=src_port, dport=priv_sport)

            new_pkt = IP(src=src_ip, dst=priv_ip) / udp_header / pkt[UDP].payload

        # make sure to send new packet to the correct network interface
        send(new_pkt, iface=PRIVATE_IFACE, verbose=False)
    except Exception as e:
        print("ERROR: ", e) 

def private_listener():
    print("sniffing packets on the private interface")
    sniff(prn=process_pkt_private, iface=PRIVATE_IFACE, filter=FILTER)


def public_listener():
    print("sniffing packets on the public interface")
    sniff(prn=process_pkt_public, iface=PUBLIC_IFACE, filter=FILTER)


def main():
    try:
        os.mkdir("logs")
    except FileExistsError:
        pass
    
    with open("logs/nat_log.txt", "w") as f:
        f.write("")

    thread1 = Thread(target=private_listener)
    thread2 = Thread(target=public_listener)

    def print_mapping_loop():
        while True:
            tcp_udp_mapping.print_mappings()
            time.sleep(0.1)

    thread3 = Thread(target=print_mapping_loop)

    print("starting multiple sniffing threads...")
    thread1.start()
    thread2.start()
    thread3.start()
    thread1.join()
    thread2.join()
    thread3.join()


main()
