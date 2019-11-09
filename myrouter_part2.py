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

	   #TODO figure out the next hop

	   #TODO get the MAC address of the next hop


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
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
		entry = ForwardingEntry(interface.ipaddr,interface.netmask)
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


'''
Main entry point for router.  Just create Router
object and get it going.
'''
def main(net):
	r = Router(net)
	table = ForwardingTable()
	initialize_forwarding_table(r,table)
	r.router_main()
	net.shutdown()