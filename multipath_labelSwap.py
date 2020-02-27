'''
Kyle Ebding
multipath_labelSwap.py

This program takes an input edgelist as a command line argument, runs a
modified version of Dijkstra's algorithm to find the set of best paths (defined
as all paths that are not worse than any other path in every metric), and
stores the paths and their metrics. The current method of storage is a
dictionary of lists, where the keys are destinations in the graph and the
values are lists of tuples, where each tuple describes a path by its hopCount,
bandwidth, and path. These dictionaries for each node are the values of a
dictionary whose keys are the nodes in the graph; in total, there is a
dictionary whose keys are nodes and whose values are dictionaries that store a
list of paths for each destination in the graph.

path tuple format: (hopCount, bw, (path), label, NHL)
'''

import networkx as nx
import sys
from heapq import *

def multipath_dijkstra(G, src):
    # create the output dictionary
    dests = {}
    for dst in G:
        dests[dst] = []     # create an empty list to store paths to this dst
        q = [(0, float('inf'), src, ())]
        while q:
            (hopCount, bw, node, path) = heappop(q)
            if node in path:
                continue
            # only proceed if the current path at this node is not dominated
            if len(dests[dst]) < 1 or \
                    hopCount < dests[dst][-1][0] or bw > dests[dst][-1][1]:
                # append the node to the path
                nodeTup = (node,)
                path = path + nodeTup
                # if the node is the dst, get the NH path
                if node == dst:
                    dests[dst].append((hopCount, bw, path))
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

    # now remove dominated paths that were inserted before the dominating path
    # was found
    for paths in dests.values():
        for path in paths:
            for otherPath in paths:
                if path != otherPath:
                    if path[0] <= otherPath[0] and path[1] >= otherPath[1]:
                        paths.remove(otherPath)


    return dests



def compute_mpls_labels(graph):
    paths = {}
    for node in graph:
        # multipath_dijkstra returns a dictionary with the destinations as keys and
        # lists of path tuples as values
        paths[node] = multipath_dijkstra(graph, node)

    # now add labels to each path
    for src, dstsDict in paths.items():
        label = 0
        for dst, pathsList in dstsDict.items():
            for path in range(len(pathsList)):
                # if there isn't already a label for the path, assign one
                if len(paths[src][dst][path]) < 4:
                    labelTup = (label,)
                    paths[src][dst][path] = \
                            paths[src][dst][path] + labelTup
                    label += 1
    # now compute the Next Hop Labels (NH Label or NHL)
    # find a path to the NH to get the metrics to it. check the total
    # path metrics to determine if the NH's path is the same as src's path
    for src, dstsDict in paths.items():
        for dst, pathsList in dstsDict.items():
            if src == dst:
                # assign NHL = label and append NHL to path tuple
                paths[src][dst][path] += (paths[src][dst][path][3],)
                continue
            # else
            for path in range(len(pathsList)):
                NH = paths[src][dst][path][2][1]
                NHL = -1  # placeholder
                # find matching path in NH's paths list
                for NHpath in paths[NH][dst]:
                    if NHpath[2] == paths[src][dst][path][2][1:]:
                        NHL = NHpath[3]
                        break
                if NHL == -1:
                    print("error: no next hop label found\n")
                NHLtup = (NHL,)
                paths[src][dst][path] += NHLtup

    return paths


def get_mpls_labels(paths, node, dst, maxDelay=float('inf'), minBW=0):
    ''' return a tuple (label, NHlabel) for a path from node to dst with
    the specified properties. if no such path could be found, it will return
    a path that doesn't fit those requirements '''
    if type(paths) is not dict:
        raise TypeError('input must be a dict')

    # reminder: tuple format is (hopCount, bw, NH, label, NH_label)
    for path in paths[node][dst]:
        if path[0] < maxDelay and path[1] > minBW:
            return (path[3], path[4])
    # if no paths fit the requirements, return a failure
    return None


def print_mpls_labels(paths):
    #print entries
    if type(paths) is not dict:
        raise TypeError('input must be a dict')

    for node, dstsDict in paths.items():
        print("for node " + str(node) +":")
        for dst, pathsList in dstsDict.items():
            for path in range(len(pathsList)):
                print("dst=%s, label=%d, path=%s, NHL=%d, hopCount=%d, bw=%.2f" %
                        (dst, paths[node][dst][path][3],
                            paths[node][dst][path][2],
                            paths[node][dst][path][4],
                            paths[node][dst][path][0],
                            paths[node][dst][path][1]
                        )
                    )


if __name__ == "__main__":
    edgelist = open(sys.argv[1], 'rb')
    G = nx.read_edgelist(edgelist, nodetype=int, data=(('bw', float),))
    edgelist.close()
    paths = compute_mpls_labels(G)
    print_mpls_labels(paths)
