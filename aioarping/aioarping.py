#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application is simply a python only arping library.
# It is meant to be used for presence detection using devices MAC addresses
# 
# Copyright (c) 2017 François Wautier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

import socket, asyncio,ipaddress,fcntl
from struct import pack, unpack
from functools import partial


SIOCGIFADDR = 0x8915
SIOCSIFHWADDR = 0x8927


class IPAddressingError(Exception):
    pass


def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def create_raw_socket(interface=None, family=0, proto=0):
    if interface is None:
        raise ValueError(
            'interface was not set')
    else:
        interface = interface[:15]

    if family == 0:
        family = socket.AF_PACKET
    if proto != 0:
        proto = socket.htons(proto)

    exceptions = []
    sock = None
    try:
        sock = socket.socket(family=family,
                             type=socket.SOCK_RAW,
                             proto=proto)
        sock.setblocking(False)
        try:
            sock.bind((interface, socket.SOCK_RAW))
        except OSError as exc:
            exc = OSError(
                    exc.errno, 'error while attempting to bind on '
                    'interface {!r}: {}'.format(
                        interface, exc.strerror.lower()))
            exceptions.append(exc)
    except OSError as exc:
        if sock is not None:
            sock.close()
        exceptions.append(exc)
    except:
        if sock is not None:
            sock.close()
        raise

    if len(exceptions) == 1:
        raise exceptions[0]
    elif len(exceptions) > 1:
        model = str(exceptions[0])
        if all(str(exc) == model for exc in exceptions):
            raise exceptions[0]
        raise OSError('Multiple exceptions: {}'.format(
            ', '.join(str(exc) for exc in exceptions)))
    return sock

# Classes :
###########

class ArpRequester(asyncio.Protocol):
    '''Protocol handling the requests'''
    def __init__(self):
        self.transport = None
        self.smac = None
        self.sip = None
        self.process = self.default_process
    
    def connection_made(self, transport):
        self.transport = transport
        sock = self.transport.get_extra_info("socket")
        interface = pack('256s', sock.getsockname()[0].encode('ascii'))
        info = fcntl.ioctl(sock.fileno(), SIOCSIFHWADDR, interface)
        self.smac = info[18:24]
        info = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, interface)
        self.sip = ipaddress.IPv4Address(info[20:24])
            
    def connection_lost(self, exc):
        self.loop.stop()



    def request(self, ip_addr):
        """Send ARP request, ip_addr is either, a single address, or a range of addr list of 2),
        list of addr (3 or more), or a network"""
        try:
            if isinstance(ip_addr,list):
                if len(ip_addr)==2:
                    #A range
                    if ip_addr[0] < ip_addr[1]:
                        ip_addr=ipaddress.summarize_address_range(ip_addr[0], ip_addr[1])
                    #else it is just 2 addresses
            elif isinstance(ip_addr,ipaddress.IPv4Address):
                ip_addr=[ip_addr]
            elif isinstance(ip_addr,ipaddress.IPv4Network,):
                ip_addr=[ip_addr]
            else: raise IPAddressingError
        
            #Now we have a list
            for addr in ip_addr:
                if isinstance(addr,ipaddress.IPv4Address):
                    self.send_arp_request(addr)
                else: #A network
                    self.send_arp_request(addr.network_address)
                    for x in addr.hosts():
                        self.send_arp_request(x)
                    self.send_arp_request(addr.broadcast_address)
        except:
            raise IPAddressingError
    
        
    def send_arp_request(self,ip_addr):
        '''Sending ARP request for given IP'''

        # Forge de la trame :
        frame = [
            ### ETHERNET header###
            # Destination MAC address (=broadcast) :
            pack('!6B', *(0xFF,) * 6),
            # Source MAC address :
            self.smac,
            # Type of protocol (=ARP) :
            pack('!H', 0x0806),
            
            ### ARP payload###
            # Type of protocol hw/soft (=Ethernet/IP) :
            pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
            # Operation (=ARP Request) :
            pack('!H', 0x0001),
            # Source MAC address :
            self.smac,
            # Source IP address :
            int_to_bytes(int(self.sip)),
            # Destination MAC address (what we are looking for) (=00*6) :
            pack('!6B', *(0,) * 6),
            # Target IP address:
            int_to_bytes(int(ip_addr))
        ]
        
        self.transport.write(b''.join(frame)) # Sending
        
    def data_received(self, data):
        packet = data

        ethernet_header = packet[0:14]
        ethernet_detail = unpack("!6s6s2s", ethernet_header)
        if ethernet_detail[2] == b'\x08\x06': #ARP only
            arp_header = packet[14:42]
            arp_detail = unpack("2s2s1s1s2s6s4s6s4s", arp_header)
            
            if arp_detail[4] == b'\x00\x02' and arp_detail[7]==self.smac: #Replies to me only
                self.process( 
                    {"mac":':'.join(a + b for a, b in zip(*[iter(arp_detail[5].hex())]*2)),
                        "ip":ipaddress.IPv4Address(socket.inet_ntoa(arp_detail[6]))})
                        #"destination mac":':'.join(a + b for a, b in zip(*[iter(arp_detail[7].hex())]*2)),
                        #"destination ip":ipaddress.IPv4Address(socket.inet_ntoa(arp_detail[8]))
    
    def default_process(self,data):
        pass
    

if __name__ == '__main__':
    import subprocess
    def my_process(data):
        print ("Source MAC:      {}".format(data["mac"]))
        print ("Source IP:       {}".format(data["ip"]))
        print()
        
    event_loop = asyncio.get_event_loop()
    mydomain=[x for x in subprocess.getoutput("ip route|sed '/via/d' | sed '/src /!d' | sed '/dev /!d' |sed '2,$d'").split(" ") if x]
    myiface=mydomain[2]
    mydomain=mydomain[0]
    
    #First create and configure a raw socket
    mysocket = create_raw_socket(myiface)
    
    #create a connection with the raw socket
    fac=event_loop.create_connection(ArpRequester,sock=mysocket)
    #Start it
    conn,arpctrl = event_loop.run_until_complete(fac)
    #Attach your processing 
    arpctrl.process=my_process
    print ("Probing {} on {}".format(mydomain,myiface))
    #Probe
    arpctrl.request(ipaddress.IPv4Network(mydomain))
    try:
        # event_loop.run_until_complete(coro)
        event_loop.run_forever()
    except KeyboardInterrupt:
        print('keyboard interrupt')
    finally:
        print('closing event loop')
        conn.close()
        event_loop.close()