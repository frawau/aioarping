# aioarping

aioarping is a Python 3/asyncio library to detect devices present on the LAN using
ARP.

It's single minded purpose is to detect "presence" using devices MAC address. 

I could not find anything this simple anywhere so I decided to write it myself. I am aware 
of "scapy", it is a fabulous networking toolbox, but it an overkill for the use I intended.

Also most other solutions rely on external utilities ('arping', 'tcpdump',..) this library
is python only.

# Installation

We are on PyPi so

     pip3 install aioarping
or
     python3 -m pip install aioarping
     

# How to use

Using it is quite simple.

    1- Create a raw socket:
    
            mysocket = create_raw_socket(iface)
            
               The parameter is a string, the name of the network interface
               you want to use
               
    2- Start the asyncio.Protocol
    
            ac=event_loop.create_connection(ArpRequester,sock=mysocket)
            conn,arpctrl = event_loop.run_until_complete(fac)
 
    3- Tell it what to do with the result
    
            arpctrl.process=my_process
            
                my_process should be a function that takes 1 parameter,
                a dictionary with 2 keys:
                   'mac'  the MAC address of the answering device ( a string "aa:bb:cc:dd:ee:ff)
                   'ip'   IP address of the answering device. An ipaddress.IPv4Address
               
                It will be called for every ARP response.
                
       You can also set skip_list, a list of ipaddress.IPv4Address, for those IP addresses 
       that need not be bothered
       
            arpctrl.skip_list=[ipaddress.IPv4Address("192.168.0.21")]
            
       One's own address is always added to that list. So we won't send gratuitous ARP requests.
                

                   
    4- Send the ARP request
        
            arpctrl.request(ipaddress.IPv4Network('192.168.0.0/25'))
            
                The parameter to ArpRequester can be:
                    - An ipaddress.IPv4Address
                           One request wil be sent to that address
                       
                    - An ipaddress.IPv4Network
                           One request will be sent for every address
                           inside the network, including the network
                           address and the broadcast address
                           
                    - A list of ipaddress.IPv4Address.
                           If the list has exactly 2 elements AND
                           param[0] < param[1], then the list is
                           considered a range of addresses and a request
                           is sent to each address in the range.
                           
                           In other cases, a request is sent to each address
                           in the list.
                           
                           So, without the ipaddress bit,
                           
                                ["192.168.0.3","192.168.0.10']   
                                    represents a range of addresses
                                    
                                ["192.168.0.10","192.168.0.3']   
                                    represents a list of 2 addresses
                                    
                    - A list of ipaddress.IPv4Network
                            A request is send for every host in every network.
                            (including network and broadcast addresses)
                            
                    
                Any nonsensical parameter willl cause crash, flooding, locus 
                infestation and erectile dysfunction... in that order.
                
                And might raise IPAddressinError too.
                
    The ArpRequester won't stop listening until it is closed. It is the responsablitu
    of the application to manage that.