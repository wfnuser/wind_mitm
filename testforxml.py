#coding:utf-8

import socket, SocketServer
import subprocess, select, struct
import traceback
import xml.etree.ElementTree as ET
import re
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
		
		target = raw_input('please input the key you want to replace\n')
		replace = raw_input('please input the value you want to change to\n')
		data = re.sub('(?<='+target+'=")[\w,:,\/,\.]*(?=")',replace,data)
		print "REP", data

main()