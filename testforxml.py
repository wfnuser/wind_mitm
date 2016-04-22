#coding:utf-8

import socket, SocketServer
import subprocess, select, struct
import traceback
import xml.etree.ElementTree as ET


from scapy.packet import Packet, bind_layers
from scapy.fields import *
from scapy.layers.inet import TCP
from dec import *
from scapy.all import *
import collections, json

def main():
		data = '<message id="DY2nr-34" date="1461315946972" messageid="26217e8af1543d37d4ac03fb747c89b035350" to="10235668655@sns" from="2400800273@sns/phone" type="chat"><body encrypType="0">{"msg":"Asdfghjklasdfghjkl","nickname":"好好学英语_qq1693","itype":"txt"}</body><thread>pzsDj5</thread></message>'
		print "ORG", data
		tree = ET.fromString(data)
		root = tree.getroot()
		for message in root.findall('message'): 
		    message.setAttribute('date','100000000000')

		data = ET.tostring(root, encoding='utf-8')
		print "REP", data

main()