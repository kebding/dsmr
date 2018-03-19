'''
multipath_dijkstra.py
Kyle Ebding
created 20 September 2016 

This program creates and returns a dictionary storing each destination node in
a graph as the keys with the values being lists of tuples describing paths from
the source to the destination. Only the best paths are stored (i.e. paths that
are worse by every metric than another path will be discarded). Currently, the
metrics considered are latency and bandwidth. The function is designed to work
with networkx graphs.
The path tuple is (hopCount, bandwidth, nextHop).

'''

from heapq import *

def multipath_dijkstra(G, src):
    # create the output dictionary
    dests = {}
    for dst in G:
        dests[dst] = []     # create an empty list to store paths to this dst
        q = [(0, float('inf'), src, ())]
        while q:
            (hopCount, bw, node, path) = heappop(q)
            # only proceed if the current path at this node is not dominated
            if len(dests[dst]) < 1 or \
                    hopCount < dests[dst][-1][0] or bw > dests[dst][-1][1]:
                # append the node to the path
                nodeTup = (node,)
                path = path + nodeTup
                # if the node is the dst, get the NH path
                if node == dst: 
                    if len(path) > 1:   # i.e. if src != dst
                        NH = path[1]
                    else:   # i.e. if src == dst 
                        NH = path[0]
                    # store the metrics and NH in dests, then   
                    dests[dst].append((hopCount, bw, NH))
                    continue
                
                # check the neighbors of the node; queue undominated neighbors
                for neighbor in G[node]:
                    if len(dests[dst]) < 1 or \
                            hopCount + 1 < dests[dst][-1][0] \
                            or min(bw, G[node][neighbor]['bw']) > dests[dst][-1][1]:
                        heappush(q, (hopCount + 1, 
                                min(bw, G[node][neighbor]['bw']), neighbor, path))
                # done checking neighbors for undominated paths
            # else if this path is dominated, pop the next entry from the queue
        # at this point the queue is empty. begin working on the next dst
    # all dsts have been calculated
    return dests

if __name__ == "__main__":
    edgelist = open(sys.argv[1], 'rb')
    G = nx.read_edgelist(edgelist, nodetype=int, data=(('bw', float),))
    edgelist.close()
    if sys.argv[2] is not none:
        dests = multipath_dijkstra(G, sys.argv[2])
        print(dests)
    else:
        for i in G.nodes():
            dests[i] = multipath_dijkstra(G, i)
        for item in dests:
            print(item)

