'''
Kyle Ebding
routing_labels.py

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

def _not_dominated(hops, bw, paths):
    ''' returns whether a path with the input hops and bandwidth is undominated
    by any path in the input list of paths '''
    for path in paths:
        if hops >= paths[0] and bw <= paths[1]:
            return False
    return True

def multipath_dijkstra(G, src):
    ''' computes the set of best paths from the input node src to every other
    node in the input networkX graph G '''
    dests = {}
    q = [(0, float('inf'), src, ())]
    while q:
        (hopCount, bw, node, path) = heappop(q)
        dests.setdefault(node, [])
        if node in path:
            continue
        # only proceed if the current path at this node is not dominated
        if _not_dominated(hopCount, bw, dests[node]):
            # append the node to the path
            path += (node,)
            dests[node].append((hopCount, bw, path))

            # check the neighbors of the node; queue undominated neighbors
            for neighbor in G[node]:
                dests.setdefault(neighbor, [])
                try:
                    next_hop_bw = min(bw, G[node][neighbor]['bw'])
                    if _not_dominated(hopCount + 1, next_hop_bw, dests[neighbor]):
                        heappush(q, (hopCount + 1, next_hop_bw, neighbor, path))
                except KeyError:
                    # no bw found. do not use this link
                    pass

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

    # sort the paths to each node by their hop counts
    for paths in dests.values():
        paths.sort(key=lambda path: path[0])

    return dests



def compute_mpls_labels(graph):
    ''' given an input networkX graph, this function computes the set of best
    paths in the graph and assigns MPLS labels to each path '''
    paths = {}
    for node in graph:
        # multipath_dijkstra returns a dictionary with the destinations as keys and
        # lists of path tuples as values
        paths[node] = multipath_dijkstra(graph, node)

    # now add labels to each path
    for src, dstsDict in paths.items():
        # labels 0-15 are reserved, so start at a higher number
        label = 1000
        arp_label = 100
        for dst, pathsList in dstsDict.items():
            arp_path = None  # record the shortest path
            for path in range(len(pathsList)):
                if arp_path is None or \
                        paths[src][dst][path][0] < arp_path[0]:
                    arp_path = paths[src][dst][path]
                # if there isn't already a label for the path, assign one
                if len(paths[src][dst][path]) < 4:
                    label_tup = (label,)
                    paths[src][dst][path] +=  label_tup
                    label += 1
            # add the ARP unicast path
            if arp_path is None:
                # no paths, so skip
                continue
            arp_label_tup = (arp_label,)
            arp_path += arp_label_tup
            paths[src][dst].append(arp_path)
            arp_label += 1

    # now compute the Next Hop Labels (NH Label or NHL)
    # find a path to the NH to get the metrics to it. check the total
    # path metrics to determine if the NH's path is the same as src's path
    for src, dstsDict in paths.items():
        for dst, pathsList in dstsDict.items():
            for path in range(len(pathsList)):
                NHL = -1  # placeholder
                if src == dst:
                    NHL = paths[src][dst][path][3]
                else:
                    NH = paths[src][dst][path][2][1]
                    # find matching path in NH's paths list
                    for NHpath in paths[NH][dst]:
                        if NHpath[2] == paths[src][dst][path][2][1:] and \
                                ((NHpath[3] >= 1000  and \
                                    paths[src][dst][path][3] >= 1000) \
                                or \
                                NHpath[3] < 1000 and \
                                    paths[src][dst][path][3] < 1000):
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
    ''' given an input set of paths generated by compute_mpls_labels, this
    function prints the paths in a neat, human-readable format '''
    if type(paths) is not dict:
        raise TypeError('input must be a dict')

    for node, dstsDict in paths.items():
        print("for node " + str(node) +":")
        for dst, pathsList in dstsDict.items():
            for path in range(len(pathsList)):
                try:
                    print("dst=%s, label=%d, path=%s, NHL=%d, hopCount=%d, bw=%.2f" %
                            (dst, paths[node][dst][path][3],
                                paths[node][dst][path][2],
                                paths[node][dst][path][4],
                                paths[node][dst][path][0],
                                paths[node][dst][path][1]
                            )
                        )
                except IndexError as ie:
                    print(ie)


if __name__ == "__main__":
    edgelist = open(sys.argv[1], 'rb')
    G = nx.read_edgelist(edgelist, nodetype=int, data=(('bw', float),))
    edgelist.close()
    paths = compute_mpls_labels(G)
    print_mpls_labels(paths)
