from pyvis.network import Network
import pandas as pd
from IPython.display import display, HTML

test_net = Network(height = "750px", width = "100%", bgcolor = "#222222", font_color = "white")

test_net.barnes_hut()

sources = ["10.28.203.5", "10.28.203.6", "10.28.203.7", "10.28.203.8", "10.28.203.9", "10.28.203.23"]
targets = ["10.28.203.6", "10.28.203.7", "10.28.203.8", "10.28.203.9", "10.28.203.23",  "8.8.8.8"]
weights = [10, 5, 20, 15, 10, 2]

edgedata = zip(sources, targets, weights)
for e in edgedata:
    src = e[0]
    dst = e[1]
    w = e[2]
    test_net.add_node(src, src, title = src)
    test_net.add_node(dst, dst, title = dst)
    test_net.add_edge(src, dst, value = w)

test_net.save_graph("test.html")