from pyvis.network import Network
import pandas as pd
from IPython.display import display, HTML


def createGraph(icmpNodes=[], tcpNodes=[], udpNodes=[]):
    network = Network(height = "100vh", width = "100vw", bgcolor = "#222222", font_color = "white", directed=True);
    network.barnes_hut();

    network.add_node("0.0.0.0", "0.0.0.0", title="0.0.0.0", color="red");
    edges = {};

    for key in icmpNodes.keys():
        route = icmpNodes[key];
        sources = ["0.0.0.0"]
        targets = [];
        weights = [];
        for i in range(0, len(route)):
            currentNode = list(route[i].keys())[0];
            latency1 = route[i][currentNode][0] if route[i][currentNode][0] != "*" else 0;
            latency2 = route[i][currentNode][1] if route[i][currentNode][1] != "*" else 0;
            latency3 = route[i][currentNode][2] if route[i][currentNode][2] != "*" else 0;
            averageLatency = (latency1 + latency2 + latency3) / 3
            if(i != len(route) - 1):
                sources.append(currentNode);
            targets.append(currentNode);
            weights.append(averageLatency * 1000);

        for src in sources:
            network.add_node(src, src, title=src);

        network.add_node(targets[-1], targets[-1], title=targets[-1]);

        for i in range(0, len(sources)):
            edgeHash = hash((sources[i], targets[i], "icmp"));
            if(edgeHash not in edges):
                edges[edgeHash] = {'weight': 0, 'src': sources[i], 'dst': targets[i], "color": "blue"};

            edges[edgeHash]['weight'] += 1;

    for key in tcpNodes.keys():
        route = tcpNodes[key];
        sources = ["0.0.0.0"]
        targets = [];
        weights = [];
        for i in range(0, len(route)):
            currentNode = list(route[i].keys())[0];
            latency1 = route[i][currentNode][0] if route[i][currentNode][0] != "*" else 0;
            latency2 = route[i][currentNode][1] if route[i][currentNode][1] != "*" else 0;
            latency3 = route[i][currentNode][2] if route[i][currentNode][2] != "*" else 0;
            averageLatency = (latency1 + latency2 + latency3) / 3
            if(i != len(route) - 1):
                sources.append(currentNode);
            targets.append(currentNode);
            weights.append(averageLatency * 1000);

        for src in sources:
            network.add_node(src, src, title=src);

        network.add_node(targets[-1], targets[-1], title=targets[-1]);

        for i in range(0, len(sources)):
            edgeHash = hash((sources[i], targets[i], "tcp"));
            if(edgeHash not in edges):
                edges[edgeHash] = {'weight': 0, 'src': sources[i], 'dst': targets[i], "color": "green"};

            edges[edgeHash]['weight'] += 1;

    for key in udpNodes.keys():
        route = udpNodes[key];
        sources = ["0.0.0.0"]
        targets = [];
        weights = [];
        for i in range(0, len(route)):
            currentNode = list(route[i].keys())[0];
            latency1 = route[i][currentNode][0] if route[i][currentNode][0] != "*" else 0;
            latency2 = route[i][currentNode][1] if route[i][currentNode][1] != "*" else 0;
            latency3 = route[i][currentNode][2] if route[i][currentNode][2] != "*" else 0;
            averageLatency = (latency1 + latency2 + latency3) / 3
            if(i != len(route) - 1):
                sources.append(currentNode);
            targets.append(currentNode);
            weights.append(averageLatency * 1000);

        for src in sources:
            network.add_node(src, src, title=src);

        network.add_node(targets[-1], targets[-1], title=targets[-1]);

        for i in range(0, len(sources)):
            edgeHash = hash((sources[i], targets[i], "udp"));
            if(edgeHash not in edges):
                edges[edgeHash] = {'weight': 0, 'src': sources[i], 'dst': targets[i], "color": "red"};

            edges[edgeHash]['weight'] += 1;

    for key in edges.keys():
        network.add_edge(edges[key]['src'], edges[key]['dst'], value=edges[key]['weight'], color=edges[key]['color']);

    network.save_graph("graph.html");
