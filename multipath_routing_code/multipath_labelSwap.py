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
describes a path by its hopCount, bandwidth, and next hop. These dictionaries for
each node are the values of a dictionary whose keys are the nodes in the graph;
in total, there is a dictionary whose keys are nodes and whose values are 
dictionaries that store a list of paths for each destination in the graph.

path tuple format: (hopCount, bw, NH, label, NHL)
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
    for src, destsDict in paths.items():
        for dest, pathsList in destsDict.items():
            for path in range(len(pathsList)):
                # if there isn't already a label for the path, assign one
                if len(paths[src][dest][path]) < 5:
                    label = path
                    labelTup = (label,)
                    paths[src][dest][path] = \
                            paths[src][dest][path] + labelTup
    # now compute the Next Hop Labels (NH Label or NHL)
    # find a path to the NH to get the metrics to it. check the total
    # path metrics to determine if the NH's path is the same as src's path
    for src, destsDict in paths.items():
        for dest, pathsList in destsDict.items():
            for path in range(len(pathsList)):
                NH = paths[src][dest][path][2] 
                # get the metrics to reach the NH
                NHhopCount = -1
                for foo in range(len(pathsList)):
                    if paths[src][NH][foo][2] == NH:
                        NHhopCount = paths[src][NH][foo][0]
                        break
                if NHhopCount == -1:
                    print("error: no matching path found for node %s to dest %s" % 
                            (src, dest))
                # check if hopCount to NH + hopCount from NH to dest are equal for each path
                # if so, they (probably) refer to the same path
                NHL = -1
                for foo in range(len(pathsList)):
                    if paths[NH][dest][foo][0] + NHhopCount == \
                            paths[src][dest][path][0]:
                        NHL = paths[NH][dest][foo][3]
                        break
                if NHL == -1:
                    print("error: no next hop label found")
                    break
                NHLtup = (NHL,)
                paths[src][dest][path] = paths[src][dest][path] + NHLtup
    
    return paths


def get_MPLS_labels(paths, node, dest, maxDelay=float('inf'), minBW=0):
    ''' return a tuple (label, NHlabel) for a path from node to dest with 
    the specified properties. if no such path could be found, it will return
    a path that doesn't fit those requirements '''
    if type(paths) is not dict:
        raise TypeError('input must be a dict')
    
    # reminder: tuple format is (hopCount, bw, NH, label, NH_label)
    for path in paths[node][dest]:
        if path[0] < maxDelay and path[1] > minBW:
            return (path[3], path[4])
    # if no paths fit the requirements, return a failure
    return None


def print_MPLS_labels(paths):
    #print entries
    if type(paths) is not dict:
        raise TypeError('input must be a dict')

    for node, destsDict in paths.items():
        print("for node " +  node +":")
        for dest, pathsList in destsDict.items():
            for path in range(len(pathsList)):
                print("dest: %s, label: %d, NH: %s, NHL: %d, hopCount: %.2f, bw: %.2f" % 
                        (dest, paths[node][dest][path][3], 
                            paths[node][dest][path][2], 
                            paths[node][dest][path][4], 
                            paths[node][dest][path][0],
                            paths[node][dest][path][1]
                        )
                    )


if __name__ == "__main__":
    edgelist = open(sys.argv[1], 'rb')
    G = nx.read_edgelist(edgelist, nodetype=int, data=(('bw', float),))
    edgelist.close()
    paths = compute_MPLS_labels(G)
    print_MPLS_labels(paths)
