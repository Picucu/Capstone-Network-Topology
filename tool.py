import sys;
import csv;
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

    def run(self):
        #self.tree = Tree();

        sites = ["8.8.8.8"]
        # with open("sites.csv", newline='') as csvfile:
        #     sitereader = csv.reader(csvfile, delimiter='\n');
        #     for row in sitereader:
        #         sites.append(row[0]);

        for site in sites:
            print("Tracerouting", site);
            for i in range(1, 28):
                pkti = IP(dst=site, ttl=(1,20)) / ICMP()
                pktt = IP(dst=site, ttl=(1,20)) / TCP(dport=80, flags="S")

                ansi= sr1(pkti, timeout=10)
                anst= sr1(pktt, timeout=10)
                time = ansi.time - pkti.sent_time
                ansi.sprintf("IP: %IP.src%, Time: ", time*1000)
            
            
            
            
            for r in ansi:
                print(r[1].summary(), r[1].time - r[0].sent_time)
            
            
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

            # tree.printRoute(site, "ICMP");

if(__name__ == "__main__"):
    Traceroute(sys.argv[1:]);
