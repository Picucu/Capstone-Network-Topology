import sys;
from scapy.all import IP, send, ICMP, sr, sr1, TCP, traceroute, ls;

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
        return self.value;

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

    # gets the route given a destination address
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
        print(route);

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

class Traceroute:

    def __init__(self, argv):
        self.argv = argv;

        self.run();

    def run(self):

        tree = Tree();

        res, unans = sr(IP(dst="101.231.120.158", ttl=(1,20))/ICMP(), timeout=5);
        for r in res:
            sent = r.query;
            received = r.answer;
            icmpSegment = received[ICMP];
            ipSegment = received[IP];

            tree.append(ipSegment.src, "101.231.120.158", "ICMP");
            print("Appended", ipSegment.src);
            # sometimes packets are sent again to the destination because of increasing ttl
            if(ipSegment.src == "101.231.120.158"):
                break;

        # tree.print();
        tree.print();

        # Manual traceroute
        # time = 1
        # while(True):
            # reply = sr1(IP(dst="8.8.8.8", ttl=time)/ICMP(), timeout=5);

            # tree.append(reply[IP].src, "8.8.8.8", "ICMP");

            # if(reply[ICMP].type == 0):
                # break

            # time += 1

        # time = 1
        # while(True):
            # reply = sr1(IP(dst="101.231.120.158", ttl=time)/ICMP(), timeout=5);

            # if(reply != None):
                # if(reply != None and reply[ICMP] != None):
                    # tree.append(reply[IP].src, "101.231.120.158", "ICMP");

                # if(reply[ICMP].type == 0):
                    # break

                # time += 1

        # googleRoute = tree.getRoute("8.8.8.8");
        # nyuRoute = tree.getRoute("101.231.120.158");

        tree.printRoute("101.231.120.159", "ICMP");
        print(tree.getRoute("101.231.120.159", "ICMP"))

if(__name__ == "__main__"):
    Traceroute(sys.argv[1:]);
