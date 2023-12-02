import sys;
import csv;
import argparse;
from scapy.all import IP, send, ICMP, sr, sr1, TCP, traceroute, ls, srp, Ether, UDP;

"""
Assumptions made:
1. Only ICMP packets for now
2. Site list must be IP addresses for now
"""

class Route:

    def __init__(self, dst, protocol):
        self.dst = dst;
        self.protocol = protocol;

    def __eq__(self, other):
        return other != None and self.dst == other.dst and self.protocol == other.protocol;

    def __ne__(self, other):
        return not self.__eq__(other);

    def __hash__(self):
        return hash((self.dst, self.protocol));

    def __str__(self):
        return "Destination: " + self.dst + " / Protocol: " + self.protocol;

class Node:

    def __init__(self, value):
        self.value = value;
        self.routes = {};

    def print(self):
        if(len(self.routes) != 0):
            print(self.value + "->", end="");
            for route in self.routes:
                self.routes[route].print();
        else:
            print(self.value);

    def __eq__(self, other):
        return other != None and self.value == other.value and self.routes == other.routes;

    def __str__(self):
        return "Address: " + self.value + "Routes: " + '\n'.join(self.routes);

class Tree:

    def __init__(self):
        self.root = None;

    # finds an existing node in the gree
    def find(self, address):
        nodes = [self.root];
        while(len(nodes) > 0):
            current = nodes.pop(0);
            if(current.value == address):
                return current;
            else:
                for route in current.routes:
                    nodes.append(current.routes[route]);

        return None

    def getRoute(self, destination, protocol):
        res = [self.root];
        current = self.root;
        route = Route(destination, protocol);
        while(True):
            if(route in current.routes):
                res.append(current.routes[route]);
                current = current.routes[route];
            else:
                break

        return res;

    def printRoute(self, address, protocol):
        route = self.getRoute(address, protocol);
        i = 0
        for node in route:
            if(i == len(route) - 1):
                print(node.value)
            else:
                print(node.value + '->', end="");

                i += 1

    def append(self, address, destination, protocol):
        if(self.root == None):
            self.root = Node(address);
        else:
            if(address == self.root.value):
                return;

            current = self.root;
            while(True):
                route = Route(destination, protocol);
                if(route in current.routes):
                    current = current.routes[route];
                else:
                    existingNode = self.find(address);

                    if(existingNode == None):
                        current.routes[route] = Node(address);
                    else:
                        current.routes[route] = existingNode;

                    break

    def print(self):
        self.root.print();

"""
GUI class
"""
class Traceroute:

    def __init__(self, argv):
        self.argv = argv;

        self.run();
    
    def IcmpTrc(self, i, c, addr, t=5):
        outdict = {}
        predropped = []
        for x in range(0, c):
            pkti = IP(dst=addr, ttl=i) / ICMP()
            ansi= sr1(pkti,verbose = 0, timeout=t)
            if ansi is not None:
                if ansi.src not in outdict:
                    outdict[ansi.src] = [ansi.time - pkti.sent_time]
                else:
                    outdict[ansi.src].append(ansi.time - pkti.sent_time)
            else:
                # this is horrible but it works i guess
                if len(list(outdict.keys())) == 0:
                    predropped.append("*")
                else:
                    outdict[list(outdict.keys())[len(outdict.keys())-1]].append("*")
        keys = list(outdict.keys())
        if len(list(outdict.keys())) == 0:
            outdict["*"] = c
        else:
            predropped.extend(outdict[keys[0]])
            outdict[keys[0]] = predropped
        return outdict

    def TcpTrc(self, i, c, addr, t=5):
        outdict = {}
        predropped = []
        for x in range(0,c):
            pktt = IP(dst=addr, ttl=i) / TCP(dport=80, flags="S")
            anst= sr1(pktt, verbose = 0, timeout=t)
            if anst is not None:
                if anst.src not in outdict:
                    outdict[anst.src] = [anst.time - pktt.sent_time]
                else:
                    outdict[anst.src].append(anst.time - pktt.sent_time)
            else:
                # this is horrible but it works i guess
                if len(list(outdict.keys())) == 0:
                    predropped.append("*")
                else:
                    outdict[list(outdict.keys())[len(outdict.keys())-1]].append("*")
        keys = list(outdict.keys())
        if len(list(outdict.keys())) == 0:
            outdict["*"] = c
        else:
            predropped.extend(outdict[keys[0]])
            outdict[keys[0]] = predropped
        return outdict

    def UdpTrc(self, i, c, addr, t=5):
        outdict = {}
        predropped = []
        for x in range(0,c):
            pktt = IP(dst=addr, ttl=i) / UDP(dport=80)
            anst= sr1(pktt, verbose = 0, timeout=t)
            if anst is not None:
                if anst.src not in outdict:
                    outdict[anst.src] = [anst.time - pktt.sent_time]
                else:
                    outdict[anst.src].append(anst.time - pktt.sent_time)
            else:
                # this is horrible but it works i guess
                if len(list(outdict.keys())) == 0:
                    predropped.append("*")
                else:
                    outdict[list(outdict.keys())[len(outdict.keys())-1]].append("*")
        keys = list(outdict.keys())
        if len(list(outdict.keys())) == 0:
            outdict["*"] = c
        else:
            predropped.extend(outdict[keys[0]])
            outdict[keys[0]] = predropped
        return outdict
    
    def record(self, dict, i, type):
        pkttypes ={
            1 : "ICMP",
            2: "TCP",
            3: "UDP"
        }
        for key in dict:
                out = ""
                if key == "*":
                    out = out + pkttypes[type] + " {0} ***.***.***\t".format(i) + "* " * dict[key]
                else:
                    out = out + pkttypes[type] + " {0} {1}\t".format(i, key)
                    for time in dict[key]:
                        if time == "*":
                            out = out+"\t*"
                        else:
                            out = out+"  {0:.2f}ms".format(time*1000)
                print(out)

    def run(self):
        #self.tree = Tree();

        sites = ["8.8.8.8"]
        # with open("sites.csv", newline='') as csvfile:
        #     sitereader = csv.reader(csvfile, delimiter='\n');
        #     for row in sitereader:
        #         sites.append(row[0]);

        

        for site in sites:
            #TODO add ability to specify number of pings per ttl and choosing ttl range
            #activate, deactivate tcp, udp and icmp
            print("Tracerouting", site);
            iFlag = 0
            tFlag = 0
            uFlag = 0
            ttl = 20
            iedges = []
            tedges = []
            uedges = []
            for i in range(1, ttl+1):
                #pktt = IP(dst=site, ttl=(1,20)) / TCP(dport=80, flags="S")
                #anst= sr1(pktt, timeout=10)
                
                
                # ICMP MODULE
                
                if iFlag == 0:
                    itdict = self.IcmpTrc(i, 3, site)
                    if site in itdict.keys():
                        iFlag = 1
                    self.record(itdict, i, 1)
                if tFlag == 0:
                    ttdict = self.TcpTrc(i, 3, site)
                    if site in ttdict.keys():
                        tFlag = 1
                    self.record(ttdict, i, 2)
                if uFlag == 0:
                    udict = self.UdpTrc(i, 3, site)
                    if site in udict.keys():
                        uFlag = 1
                    self.record(udict, i, 3)
            #     if reply is None:
            #         print("No reply")
            #         continue
            #     else:
            #         if(reply.src == site):
            #             print("Reached end", reply.src);
            #             tree.append(reply.src, site, "ICMP");
            #             break

            #         tree.append(reply.src, site, "ICMP");
            #         print("%d hops away: " % i , reply.src)

            # tree.printRoute(site, "ICMP")
        

if(__name__ == "__main__"):
    Traceroute(sys.argv[1:]);
