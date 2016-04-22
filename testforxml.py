#coding:utf-8

import socket, SocketServer
import subprocess, select, struct
import traceback
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import XML, fromstring, tostring
from inspect import getmembers
from pprint import pprint


from scapy.packet import Packet, bind_layers
from scapy.fields import *
from scapy.layers.inet import TCP
from dec import *
from scapy.all import *
import collections, json

def main():
		data = '<stream:stream to="sns" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0"></stream>'
		print "ORG", data
		tree = ET.ElementTree(ET.fromstring(data))
		root = tree.getroot()

		for message in root.findall('message'): 
			message.set('date','100000000000')

		data = ET.tostring(root, encoding='utf-8')
		print "REP", data

main()