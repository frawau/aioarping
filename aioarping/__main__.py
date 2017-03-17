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

import subprocess, asyncio, aioarping, ipaddress

def my_process(data):
    print ("Source MAC:      {}".format(data["mac"]))
    print ("Source IP:       {}".format(data["ip"]))
    print()
    
event_loop = asyncio.get_event_loop()
mydomain=[x for x in subprocess.getoutput("ip route|sed '/via/d' | sed '/src /!d' | sed '/dev /!d' |sed '2,$d'").split(" ") if x]
myiface=mydomain[2]
mydomain=mydomain[0]

#First create and configure a raw socket
mysocket = aioarping.create_raw_socket(myiface)

#create a connection with the raw socket
fac=event_loop.create_connection(aioarping.ArpRequester,sock=mysocket)
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