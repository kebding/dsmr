'''
Kyle Ebding
multipath_labelSwap.py
created: 21 September 2016
updated for implementation: 26 October 2017

This program takes an input edgelist as a command line argument, runs a 
modified version of Dijkstra's algorithm to find the set of best paths, and 
stores the next hops with the path's metrics. 
The current method of storage is a dictionary of lists, where the keys are 
destinations in the graph and the values are lists of tuples, where each tuple
describes a path by its hopCount, bandwidth, and path. These dictionaries for
each node are the values of a dictionary whose keys are the nodes in the graph;
in total, there is a dictionary whose keys are nodes and whose values are 
dictionaries that store a list of paths for each destination in the graph.

path tuple format: (hopCount, bw, (path), label, NHL)
'''

import networkx as nx 
import sys
from multipath_dijkstra import multipath_dijkstra


def compute_MPLS_labels(graph):
    ''' 
    if type(graph) is not nx.classes.digraph.DiGraph or type(graph) is not nx.classes.graph.Graph:
        raise TypeError('input must be a networkx graph or digraph')
    '''
    paths = {}
    for node in graph:
        # multipath_dijkstra returns a dictionary with the destinations as keys and
        # lists of path tuples as values
        paths[node] = multipath_dijkstra(graph, node)

    # now add labels to each path
    for src, dstsDict in paths.items():
        for dst, pathsList in dstsDict.items():
            for path in range(len(pathsList)):
                # if there isn't already a label for the path, assign one
                if len(paths[src][dst][path]) < 4:
                    label = path
                    labelTup = (label,)
                    paths[src][dst][path] = \
                            paths[src][dst][path] + labelTup
    # now compute the Next Hop Labels (NH Label or NHL)
    # find a path to the NH to get the metrics to it. check the total
    # path metrics to determine if the NH's path is the same as src's path
    for src, dstsDict in paths.items():
        for dst, pathsList in dstsDict.items():
            if src == dst:
                # assign NHL = label and append NHL to path tuple
                paths[src][dst][path] += (paths[src][dst][path][3],)
                break
            # else 
            for path in range(len(pathsList)):
                NH = paths[src][dst][path][2][1]
                NHL = -1  # placeholder
                # find matching path in NH's paths list
                for NHpath in paths[NH][dst]:
                    if NHpath == paths[src][dst][path][2][1:]:
                        NHL = NHpath[3]
                        break
                if NHL == -1:
                    print("error: no next hop label found\n")
                NHLtup = (NHL,)
                paths[src][dst][path] += NHLtup
    
    return paths


def get_MPLS_labels(paths, node, dst, maxDelay=float('inf'), minBW=0):
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


def print_MPLS_labels(paths):
    #print entries
    if type(paths) is not dict:
        raise TypeError('input must be a dict')

    for node, dstsDict in paths.items():
        print("for node " +  node +":")
        for dst, pathsList in dstsDict.items():
            for path in range(len(pathsList)):
                print("dst: %s, label: %d, NH: %s, NHL: %d, hopCount: %.2f, bw: %.2f" % 
                        (dst, paths[node][dst][path][3], 
                            paths[node][dst][path][2], 
                            paths[node][dst][path][4], 
                            paths[node][dst][path][0],
                            paths[node][dst][path][1]
                        )
                    )


if __name__ == "__main__":
    edgelist = open(sys.argv[1], 'rb')
    G = nx.read_edgelist(edgelist, nodetype=int, data=(('hc', int),('bw', float)))
    edgelist.close()
    paths = compute_MPLS_labels(G)
    print_MPLS_labels(paths)