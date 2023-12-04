import sys;
import csv;
import argparse;
from scapy.all import IP, send, ICMP, sr, sr1, TCP, traceroute, ls, srp, Ether, UDP;

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
                print(ansi);
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
                # this is horrible but it works i guess
                if len(list(outdict.keys())) == 0:
                    predropped.append("*")
                else:
                    outdict[list(outdict.keys())[len(outdict.keys())-1]].append("*")
    def record(self, dict, i):
        for key in dict:
            out = ""
            if key == "*":
                out = out + "{0} ***.***.***\t".format(i) + "* " * dict[key]
            else:
                out = out+"{0} {1}\t".format(i, key)
                for time in dict[key]:
                    if time == "*":
                        out = out+"\t*"
                    else:
                        out = out+"  {0:.2f}ms".format(time*1000)
            print(out)

    def run(self):

        sites = ["8.8.8.8"]

        for site in sites:
            #TODO add ability to specify number of pings per ttl and choosing ttl range
            #activate, deactivate tcp, udp and icmp
            print("Tracerouting", site);
            iFlag = 0
            tFlag = 0
            uFlag = 0
            ttl = 20
            for i in range(1, ttl+1):
                #pktt = IP(dst=site, ttl=(1,20)) / TCP(dport=80, flags="S")
                #anst= sr1(pktt, timeout=10)
                
                
                # ICMP MODULE
                
                if iFlag == 0:
                    itdict = self.IcmpTrc(i, 3, site);
                    if site in itdict.keys():
                        iFlag = 1
                    self.record(itdict, i)
                    # for times in range(0,5):
                    #     if iFlag == 0:
                    #         pkti = IP(dst=site, ttl=i) / ICMP()
                    #         ansi= sr1(pkti,verbose = 0, timeout=10)
                    #     if ansi is not None:
                    #         if ansi.src == site:
                    #             if ansi.src not in itdict:
                    #                 itdict[ansi.src] = [time]
                    #             else:
                    #                 itdict[ansi.src].append(time)
                    #             iFlag = 1
                    #         if ansi is not None and iFlag == 0:
                    #             time = ansi.time - pkti.sent_time
                    #             if ansi.src not in itdict:
                    #                 itdict[ansi.src] = [time]
                    #             else:
                    #                 itdict[ansi.src].append(time)
                    #         elif ansi is None:
                    #             itdict[ansi.src].append("*")
                    #             ansi = None
                    #     elif ansi is None and iFlag == 0:
                    #         itdict["*"] = ["*"]
                    #         ansi = None
                
                
                # TCP MODULE
                
                
                
                
                
            
            
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
