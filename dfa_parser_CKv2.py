#!/usr/bin/python

import operator
import xml.etree.ElementTree as etree
import sys

'''                                         
Because this program parses XML, there are
vulnerabilites waiting to be exploited. Be sure to
validate the XML before giving it to this program.

Author: Carl Kenny
Usage:  Python dfa_parser_CK.py yourDFA.jff 
'''

def parseXML(xmlFile):
    """ Parses a .jff file, which is almost equivalent to
        xml ver=1.0, encoding=UTF-8 """

    tree = etree.parse(xmlFile)
    root = tree.getroot()    
    transitionTable = dict()
    transitionTable = getTransitions(tree, root, transitionTable)
    return tree, root, transitionTable

def getTransitions(tree, root, transitionTable):
    """ Finds transitions and returns the transition table """

    for transition in root.iter('transition'):
        # iter(), searches recursively over all sub-trees
        for path in transition.iter('from'):
            From = path.text

        for path in transition.iter('to'):
            To = path.text

        for path in transition.iter('read'):
            # None is considered Epsilon
            if path.text == None:
                Symbol = 'Epsilon'
            else:
                Symbol = path.text

        table = {From:[[To, Symbol]]}

        if From in transitionTable.keys():
            # Check if an entry already exists for that node
            transitionTable[From].append([To, Symbol])
        else:
            # Make new entry
            transitionTable.update(table)
   
    return transitionTable

def findInitialAndFinal(tree, root, xmlFile):
    """ Finds the initial and final states """
    finalStates = [] 
    for states in root.iter('state'):
        for final in states.iter('final'):
            # Uses 'id' to return the value of the final node(s)
            finalStates.append(states.attrib['id'])

    return finalStates

def formatOutput(tranisitionTable):
    """ Takes the transition table and formats it for quiz server """
   
    # TODO: Make all the processing done in this function, rather than main
    for key in sorted(transitionTable.iterkeys()):
        transitionTable[key].sort(key = operator.itemgetter(1)) #.sort is in-place
       
    return transitionTable 

if __name__ == '__main__':
    # TODO: Shift this into formatOuput(), fix this digusting format hacking
    xmlFile = sys.argv[1] 
    tree, root, transitionTable = parseXML(xmlFile)
    finalStates = findInitialAndFinal(tree, root, transitionTable)
    output = formatOutput(transitionTable)

    # Print the dictionary out in order of nodes (i.e. q0, q1,..., qn)
    quizPrintout = []
    for key, value in sorted(output.iteritems(), key=operator.itemgetter(0)): 
        quizPrintout.append([key, value])
        #for item in value:
            #quizPrintout.append([item[0]])

    # Convert list of strs -> list of ints
    # quizPrintout = list(map(int, quizPrintout))

    quizPrintout.append(finalStates)
    print(quizPrintout)
    

    
