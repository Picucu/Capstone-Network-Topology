import sys;import csv;
import argparse;
import re;
import pandas as pd;
from visualizer import createGraph;
from scapy.all import IP, send, ICMP, sr, sr1, TCP, traceroute, ls, srp, Ether, UDP, get_if_addr, conf;

class Traceroute:

    def __init__(self, argv):
        args = {
            'udp': "-udp" in argv,
            'tcp': "-tcp" in argv,
            'icmp': "-icmp" in argv,
            'ttlStart': int(re.search(r'-ttlStart=[0-9]+', ' '.join(argv)).group(0).split('=')[1]) if re.search(r'-ttlStart=[0-9]+', ' '.join(argv)) else 1,
            'ttlEnd': int(re.search(r'-ttlEnd=[0-9]+', ' '.join(argv)).group(0).split('=')[1]) if re.search(r'-ttlEnd=[0-9]+', ' '.join(argv)) else 20,
        }

        if(args['ttlStart'] > args['ttlEnd']):
            print("TTL start must be smaller than TTL end");
            return

        if(args['udp'] == False and args['tcp'] == False and args['icmp'] == False):
            args['udp'] = True;
            args['tcp'] = True;
            args['icmp'] = True;

        # createGraph([]);
        self.run(args);
    
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

    def run(self, args):
        sites = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "208.67.222.222"]
        # sites = ["8.8.8.8", "1.1.1.1"];
        # sites = ["1.1.1.1"];
        ownIP = get_if_addr(conf.iface);
        icmpRoutes = {};
        tcpRoutes = {};
        udpRoutes = {};
        for site in sites:
            #TODO add ability to specify number of pings per ttl and choosing ttl range
            #activate, deactivate tcp, udp and icmp
            print("Tracerouting", site);
            iFlag = 0
            tFlag = 0
            uFlag = 0
            for i in range(args['ttlStart'], args['ttlEnd']):
                if(args['icmp']):
                    if iFlag == 0:
                        itdict = self.IcmpTrc(i, 3, site, 0.1)
                        if site in itdict.keys():
                            iFlag = 1
                        if(site not in icmpRoutes.keys()):
                            icmpRoutes[site] = [];

                        if(list(itdict.keys())[0] != "*"):
                            icmpRoutes[site].append(itdict)
                        self.record(itdict, i, 1)
                if(args['tcp']):
                    if tFlag == 0:
                        ttdict = self.TcpTrc(i, 3, site, 0.1)
                        if site in ttdict.keys():
                            tFlag = 1
                        if(site not in tcpRoutes.keys()):
                            tcpRoutes[site] = [];

                        if(list(ttdict.keys())[0] != "*"):
                            tcpRoutes[site].append(ttdict)
                        self.record(ttdict, i, 2)
                if(args['udp']):
                    if uFlag == 0:
                        udict = self.UdpTrc(i, 3, site, 0.1)
                        if site in udict.keys():
                            uFlag = 1
                        if(site not in udpRoutes.keys()):
                            udpRoutes[site] = [];

                        if(list(udict.keys())[0] != "*"):
                            udpRoutes[site].append(udict)
                        self.record(udict, i, 3)

        print(icmpRoutes)
        #createGraph(icmpRoutes, tcpRoutes, udpRoutes);
        # we need 5 different pieces of information end point, src, dst, latency, protocol
        # print(icmpRoutes.keys())
        # for key in icmpRoutes.keys():
        #     print(icmpRoutes[key])

        #     for i in icmpRoutes[key]:

        f = open("icmpdata.csv", "w")
        f.write("")
        f.close()
        for key in icmpRoutes.keys():
            f = open("icmpdata.csv", "a")
            f.write(key + ","+",")
            f.write("\n,,\n")
            f.close()
            fields = ["src","dst","delay"]
            src = [ownIP]
            dst = []
            delay = []
            for i in icmpRoutes[key]:
                avg = 0
                c = 0
                for j in i[list(i.keys())[0]]:
                    if j != "*":
                        c+=1
                        avg += j
                avg = avg/c
                dst.append(list(i.keys())[0])
                src.append(list(i.keys())[0])
                delay.append(avg)
            src = src[:-1]
            x = zip(src, dst, delay)
            f = open("icmpdata.csv", "a")
            writer = csv.writer(f, dialect="unix")
            writer.writerow(fields)
            for row in x:
                writer.writerow(row)
            f.write(",,\n,,\n")
            f.close()
        f = open("tcpdata.csv", "w")
        f.write("")
        f.close()
        for key in tcpRoutes.keys():
            f = open("tcpdata.csv", "a")
            f.write(key + ","+",")
            f.write("\n,,\n")
            f.close()
            fields = ["src","dst","delay"]
            src = [ownIP]
            dst = []
            delay = []
            for i in tcpRoutes[key]:
                avg = 0
                c = 0
                for j in i[list(i.keys())[0]]:
                    if j != "*":
                        c+=1
                        avg += j
                avg = avg/c
                dst.append(list(i.keys())[0])
                src.append(list(i.keys())[0])
                delay.append(avg)
            src = src[:-1]
            x = zip(src, dst, delay)
            f = open("tcpdata.csv", "a")
            writer = csv.writer(f, dialect="unix")
            writer.writerow(fields)
            for row in x:
                writer.writerow(row)
            f.write(",,\n,,\n")
            f.close()
        f = open("udpdata.csv", "w")
        f.write("")
        f.close()
        for key in udpRoutes.keys():
            f = open("udpdata.csv", "a")
            f.write(key + ","+",")
            f.write("\n,,\n")
            f.close()
            fields = ["src","dst","delay"]
            src = [ownIP]
            dst = []
            delay = []
            for i in udpRoutes[key]:
                avg = 0
                c = 0
                for j in i[list(i.keys())[0]]:
                    if j != "*":
                        c+=1
                        avg += j
                avg = avg/c
                dst.append(list(i.keys())[0])
                src.append(list(i.keys())[0])
                delay.append(avg)
            src = src[:-1]
            x = zip(src, dst, delay)
            f = open("udpdata.csv", "a")
            writer = csv.writer(f, dialect="unix")
            writer.writerow(fields)
            for row in x:
                writer.writerow(row)
            f.write(",,\n,,\n")
            f.close()
    
        


if(__name__ == "__main__"):
    Traceroute(sys.argv[1:]);
