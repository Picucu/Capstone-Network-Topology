from pyvis.network import Network
import pandas as pd
import csv
from IPython.display import display, HTML


# def createGraph(icmpNodes=[], tcpNodes=[], udpNodes=[]):
#     network = Network(height = "100vh", width = "100vw", bgcolor = "#222222", font_color = "white", directed=True);
#     network.barnes_hut();

#     network.add_node("0.0.0.0", "0.0.0.0", title="0.0.0.0", color="red");
#     edges = {};

#     for key in icmpNodes.keys():
#         route = icmpNodes[key];
#         sources = ["0.0.0.0"]
#         targets = [];
#         weights = [];
#         for i in range(0, len(route)):
#             currentNode = list(route[i].keys())[0];
#             latency1 = route[i][currentNode][0] if route[i][currentNode][0] != "*" else 0;
#             latency2 = route[i][currentNode][1] if route[i][currentNode][1] != "*" else 0;
#             latency3 = route[i][currentNode][2] if route[i][currentNode][2] != "*" else 0;
#             averageLatency = (latency1 + latency2 + latency3) / 3
#             if(i != len(route) - 1):
#                 sources.append(currentNode);
#             targets.append(currentNode);
#             weights.append(averageLatency * 1000);

#         for src in sources:
#             network.add_node(src, src, title=src);

#         network.add_node(targets[-1], targets[-1], title=targets[-1]);

#         for i in range(0, len(sources)):
#             edgeHash = hash((sources[i], targets[i], "icmp"));
#             if(edgeHash not in edges):
#                 edges[edgeHash] = {'weight': 0, 'src': sources[i], 'dst': targets[i], "color": "blue"};

#             edges[edgeHash]['weight'] += 1;
#     print(edges)

#     for key in tcpNodes.keys():
#         route = tcpNodes[key];
#         sources = ["0.0.0.0"]
#         targets = [];
#         weights = [];

#         for i in range(0, len(route)):
#             currentNode = list(route[i].keys())[0];
#             latency1 = route[i][currentNode][0] if route[i][currentNode][0] != "*" else 0;
#             latency2 = route[i][currentNode][1] if route[i][currentNode][1] != "*" else 0;
#             latency3 = route[i][currentNode][2] if route[i][currentNode][2] != "*" else 0;
#             averageLatency = (latency1 + latency2 + latency3) / 3
#             if(i != len(route) - 1):
#                 sources.append(currentNode);
#             targets.append(currentNode);
#             weights.append(averageLatency * 1000);

#         for src in sources:
#             network.add_node(src, src, title=src);

#         network.add_node(targets[-1], targets[-1], title=targets[-1]);

#         for i in range(0, len(sources)):
#             edgeHash = hash((sources[i], targets[i], "tcp"));
#             if(edgeHash not in edges):
#                 edges[edgeHash] = {'weight': 0, 'src': sources[i], 'dst': targets[i], "color": "green"};

#             edges[edgeHash]['weight'] += 1;

#     for key in udpNodes.keys():
#         route = udpNodes[key];
#         sources = ["0.0.0.0"]
#         targets = [];
#         weights = [];
#         for i in range(0, len(route)):
#             currentNode = list(route[i].keys())[0];
#             latency1 = route[i][currentNode][0] if route[i][currentNode][0] != "*" else 0;
#             latency2 = route[i][currentNode][1] if route[i][currentNode][1] != "*" else 0;
#             latency3 = route[i][currentNode][2] if route[i][currentNode][2] != "*" else 0;
#             averageLatency = (latency1 + latency2 + latency3) / 3
#             if(i != len(route) - 1):
#                 sources.append(currentNode);
#             targets.append(currentNode);
#             weights.append(averageLatency * 1000);

#         for src in sources:
#             network.add_node(src, src, title=src);

#         network.add_node(targets[-1], targets[-1], title=targets[-1]);

#         for i in range(0, len(sources)):
#             edgeHash = hash((sources[i], targets[i], "udp"));
#             if(edgeHash not in edges):
#                 edges[edgeHash] = {'weight': 0, 'src': sources[i], 'dst': targets[i], "color": "red"};

#             edges[edgeHash]['weight'] += 1;

#     for key in edges.keys():
#         network.add_edge(edges[key]['src'], edges[key]['dst'], value=edges[key]['weight'], color=edges[key]['color']);

#     network.save_graph("graph.html");

def csv_record_reader(csv_reader):
    prev_row_blank = True
    for row in csv_reader:
        row_blank = (row[0] == '')
        if not row_blank:
            yield row
            prev_row_blank = False
        elif not prev_row_blank:
            return

def readInput(file):
    data = {}
    of = open("icmpdata.csv", "r")
    datareader = csv.reader(of)
    while True:
        finalIp = list(csv_record_reader(datareader))
        if len(finalIp) == 0:
            break
        labels = finalIp[0][0]
        #print(finalIp)
        datagen = csv_record_reader(datareader)
        columns = next(datagen)
        data[labels] = pd.DataFrame(datagen, columns=columns)
    of.close()
    return data
def createGraph():
    network = Network(height = "100vh", width = "100vw", bgcolor = "#222222", font_color = "white", directed=True, select_menu=True, filter_menu=True);
    network.barnes_hut();
    edges = {}
    data = readInput("icmpdata.csv")
    self = data[list(data.keys())[1]]["src"][0]
    network.add_node(self, self, title=self, color="red");
    for x in data.keys():
        src = data[x]["src"].tolist()
        dst = data[x]["dst"].tolist()
        delay = data[x]["delay"].tolist()
        gData = zip(src, dst, delay)
        for d in gData:
            network.add_node(d[0], d[0], title=d[0]);
            network.add_node(d[1], d[1], title=d[1]);
            edgeHash = hash((d[0], d[1], "icmp"));
            if(edgeHash not in edges):
                edges[edgeHash] = {'weight': 0, 'src': d[0], 'dst': d[1], "color": "blue"};

                edges[edgeHash]['weight'] += 1;
    
    data = readInput("tcpdata.csv")
    for x in data.keys():
        src = data[x]["src"].tolist()
        dst = data[x]["dst"].tolist()
        delay = data[x]["delay"].tolist()
        gData = zip(src, dst, delay)
        for d in gData:
            network.add_node(d[0], d[0], title=d[0]);
            network.add_node(d[1], d[1], title=d[1]);
            edgeHash = hash((d[0], d[1], "tcp"));
            if(edgeHash not in edges):
                edges[edgeHash] = {'weight': 0, 'src': d[0], 'dst': d[1], "color": "green"};

                edges[edgeHash]['weight'] += 1;
    data = readInput("udpdata.csv")
    for x in data.keys():
        src = data[x]["src"].tolist()
        dst = data[x]["dst"].tolist()
        delay = data[x]["delay"].tolist()
        gData = zip(src, dst, delay)
        for d in gData:
            network.add_node(d[0], d[0], title=d[0]);
            network.add_node(d[1], d[1], title=d[1]);
            edgeHash = hash((d[0], d[1], "udp"));
            if(edgeHash not in edges):
                edges[edgeHash] = {'weight': 0, 'src': d[0], 'dst': d[1], "color": "red"};

                edges[edgeHash]['weight'] += 1;
    for key in edges.keys():
        network.add_edge(edges[key]['src'], edges[key]['dst'], value=edges[key]['weight'], color=edges[key]['color']);
    #network.show_buttons()
    network.set_options("""
    const options = {
        "physics": {
            "barnesHut": {
            "theta": 0.4,
            "gravitationalConstant": -80000,
            "centralGravity": 0.8,
            "springLength": 100,
            "springConstant": 0.35,
            "damping": 0.07,
            "avoidOverlap": 1
            },
            "minVelocity": 0.75
        }
        }""")
    network.save_graph("graph.html")

createGraph();