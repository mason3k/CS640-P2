#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.arp_table={}
        self.my_interface = net.interfaces()
        self.forwarding_table = ForwardingTable()
        self.arp_queue = []

    def ipv4_destination_is_me(self,dest):
        for interface in self.my_interface:
           if interface.ipaddr == dest:
               return True
        return False

    def arp_actions(self,pkt):
        arp = pkt.get_header(Arp)

		# Reply
        if arp.Operation == ArpOperation.Reply:
            for intf in my_interfaces:
                if intf.ipaddr == arp.targetprotoaddr:
                    self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr

		# Request
        else:
			# we have to check both my_interfaces (interfaces in my router) and arp_table (not in my router but what I know)?

			# checking arp_table to see if arp.targetprotoaddr is in my table
            if arp.targetprotoaddr in self.arp_table:
				# create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
				# now, sender = whoever sent this to me target = me
				# for reply, I am the sender and target is whoever sent this
                reply = create_ip_arp_reply(self.arp_table[arp.targetprotoaddr], arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)

                # reply back
                self.net.send_packet(dev, reply)

                 # checking my_interfaces
            else:
                for intf in self.my_interface:
                    if intf.ipaddr == arp.targetprotoaddr:
                        reply = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)

                        self.net.send_packet(dev, reply)

    def ipv4_actions(self,pkt):
        ipv4_header = pkt.get_header(IPv4)

	    #decrement TTL by 1
        ipv4_header.ttl = ipv4_header.ttl - 1

        entry = self.forwarding_table.matching_entry(ipv4_header.dst)

		#Not in our table, so drop
        if entry == None:
            return

		#If the packet is for us, drop/ignore it
        if self.ipv4_destination_is_me(ipv4_header.dst):
             return

	    #We either have an next hop for the entry or the entry is our final destination
        if entry.next_hop != None:
            dest_ip_address = entry.next_hop
        else:
            dest_ip_address = ipv4_header.dst
        
        #Either we have the ARP address already mapped or we gotta query for it
        if dest_ip_address in self.arp_table:
              mac_addr = self.arp_table[dest_ip_address]
        else:
             query_arp = 1

		#Add packet to ARP queue
        if query_arp == 1:
            arp_queue_entry = ArpQueueEntry(dest_ip_address,entry,pkt)
            self.arp_queue.append(arp_queue_entry)
        else:
            self.create_and_send_ethernet_packet(pkt,mac_addr,entry)

    def create_and_send_ethernet_packet(pkt,mac_addr,entry):
        #create an Ethernet packet and send it out since we know mac_addr/interface name to send it on
        forward_pkt = pkt
        forward_pkt[0].dst = mac_addr
        #TODO update time of use of ARP entry!

        for intf in self.my_interface:
            if intf.name == entry.interface_name:
                forward_pkt[0].src = intf.ethaddr
                self.net.send_packet(intf,forward_pkt)

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        #Initialize forwarding table from file and my_interface
        initialize_forwarding_table(self,self.forwarding_table)
        
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

                # we do something only if it's an ARP request/reply
                if pkt.has_header(Arp):
                    self.arp_actions(pkt)

                if pkt.has_header(IPv4):
                    self.ipv4_actions(pkt)

            #Process ARP queue
            for arp_queue_item in self.arp_queue:
                entry = arp_queue_item.fw_table_entry
                time_dif = time.time() - arp_queue_item.last_request_time
                if arp_queue_item.dest_ip in self.arp_table:
                    mac_addr = self.arp_table[arp_queue_item.dest_ip]
                    pkt = arp_queue_item.pkt
                    self.create_and_send_ethernet_packet(pkt,mac_addr,entry)
                    
                    self.arp_queue.remove(arp_queue_item)

                elif time_dif >= 1:
                    arp_queue_item.retries = arp_queue_item.retries + 1
                    if arp_queue_item.retries >= 4:
                        self.arp_queue.remove(arp_queue_item)
                    else:
                        arp_queue_item.last_request_time = time.time()
                        for interface in self.my_interface:
                            if entry.interface_name == interface.name:
                                arp_request = create_ip_arp_request(interface.ethaddr,interface.ipaddr,arp_queue_item.dest_ip)

                                self.net.send_packet(interface.name,arp_request)


class ForwardingTable:
	table

	def __init__(self):
		self.table = []

	def parse_fileline(self,line):
		line_list = line.split(" ",4)
		net_address = line_list[0]
		mask = line_list[1]
		next_hop = line_list[2]
		interface_name = line_list[3]
		entry = ForwardingEntry(net_address,mask,next_hop,interface_name)
		self.table.append(entry)

	def parse_interface_object(self,interface):
		entry = ForwardingEntry(interface.ipaddr,interface.netmask,None,interface.name)
		self.table.append(entry)

	'''
	Can return None if no matches found
	'''
	def matching_entry(self,dest_addr):
		max_prefix_len = 0
		cur_entry = None
		for entry in self.table:
			if entry.is_match(dest_addr):
				prefix_len = entry.prefix_length()
				if prefix_len > max_prefix_len:
					cur_entry = entry
					max_prefix_len = prefix_len

		return cur_entry

class ForwardingEntry:
	net_prefix #this is an ip address
	net_mask
	next_hop
	interface_name 

	def __init__(self,net_prefix,net_mask,next_hop = None,interface_name = None):
		self.net_prefix = net_prefix
		self.net_mask = net_mask
		self.next_hop = next_hop
		self.interface_name = interface_name

	def is_match(self,dest_addr):
		ipv4_prefix = self.net_prefix + "/" + self.net_mask
		return dest_addr in ipv4_prefix

	def prefix_length(self):
		ipv4_prefix = self.net_prefix + "/" + self.net_mask
		return ipv4_prefix.prefixlen

def initialize_forwarding_table(router,table):
	#Add interfaces from net_interfaces() to forwarding table
	for interface in router.my_interface:
		table.parse_interface_object(interface)

	#Add interfaces from file to forwarding table
	f = open("forwarding_table.txt", "r")
	for line in f:
		table.parse_fileline(line)
	return

class ArpQueueEntry:
    def __init__(self,dest_ip,fw_table_entry = None, pkt = None, last_request_time = time.time()):
        self.last_request_time = last_request_time
        self.retries = 0
        self.fw_table_entry = fw_table_entry
        self.pkt = pkt
        self.dest_ip = dest_ip




'''
Main entry point for router.  Just create Router
object and get it going.
'''
def main(net):
	r = Router(net)
	r.router_main()
	net.shutdown()
