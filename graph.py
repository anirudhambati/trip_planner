from itertools import combinations
import math
import networkx as nx

def dist(a,b):
    return math.sqrt((int(a[0])-int(b[0]))**2 + (int(a[1])-int(b[1]))**2)

def get_graph(data):
    edges = ((s[0],t[0],dist(s[1], t[1])) for s,t in combinations(enumerate(data),2))
    G = nx.Graph()
    G.add_weighted_edges_from(edges)
    G.edges(data=True)
    return G

def dijkstra(G):
    return G

# data = [[1,2],[2,1],[3,5],[6,3]]
# a = ((s[0],t[0],dist(s[1], t[1])) for s,t in combinations(enumerate(data),2))
# for b in a:
#     print(b)
