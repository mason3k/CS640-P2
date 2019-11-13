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
                    arp = pkt.get_header(Arp)

                    # Reply
                    if arp.Operation == ArpOperation.Reply:
                        for intf in self.my_interface:
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

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
