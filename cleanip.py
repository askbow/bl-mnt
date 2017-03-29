#!/usr/bin/env python

# name: cleanip.py
# 
# description: Draconically optimizes a list of IP addresses in an attempt to compress it.
#              As a result, this list will block larger IP ranges than the original list.
#              This is basically a more aggressive version of cidr_merge(). cidr_merge() is
#              standards compliant and precise in its results (which is good), but it's not 
#              aggressive enough for automatic whole-network blacklistings.
#              Supports both IPv6 and IPv4 in the same list.
#
# usage: ./cleanip.py longiplist.txt > cleaniplist.txt
#
# author: Denis Borchev 
# license: MIT (see LICENSE for details)

import sys
from netaddr import *

def ipThreesomeMerge(iplist, ipv4len = 24, ipv6len = 64, lengap=0, threshold = 3):
    superlist = dict()
    maxlen = 128
    minlen = 0
    retlist = []
    for ip in iplist:
        if ip.version == 4: 
            maxlen = ipv4len
            if lengap==0: minlen = 32
            else: minlen = maxlen+lengap
        if ip.version == 6: 
            maxlen = ipv6len
            if lengap==0: minlen = 128
            else: minlen = maxlen+lengap
        if ip.prefixlen > maxlen and minlen>=ip.prefixlen:
            if ip.supernet(maxlen)[0] in superlist:
                superlist[ip.supernet(maxlen)[0]]+=1
            else:
                superlist[ip.supernet(maxlen)[0]]=1
        retlist.append(ip)
    for ipnet in superlist:
        if superlist[ipnet] >= threshold:
            retlist.append(ipnet)
    return cidr_merge(retlist)

def ipv6subnet64(iplist):
    retlist = []
    for ip in iplist:
        if ip.version == 6:
            if ip.prefixlen >= 64:
                ip.prefixlen = 64
                ip = ip.cidr
        retlist.append(ip)
    return retlist

def main():
    iplist = list()
    try:
        with open (sys.argv[1], "r") as fp:
            iplist = [IPNetwork(q) for q in fp.read().splitlines()]
    iplist.sort()
    iplist = ipv6subnet64(iplist)
    iplist = ipThreesomeMerge(iplist)
    iplist = ipThreesomeMerge(iplist, ipv4len = 22, ipv6len = 48, lengap=2)
    iplist = ipThreesomeMerge(iplist, ipv4len = 20, ipv6len = 44, lengap=2)
    iplist = ipThreesomeMerge(iplist, ipv4len = 16, ipv6len = 40, lengap=4)
    iplist = ipThreesomeMerge(iplist, ipv4len = 12, ipv6len = 36, lengap=4)
    iplist = ipThreesomeMerge(iplist, ipv4len = 10, ipv6len = 34, lengap=2)
    iplist = ipThreesomeMerge(iplist, ipv4len = 8, ipv6len = 32, lengap=2)
    for i in iplist:
        print i

if __name__ == '__main__':
    main()
# EOF
