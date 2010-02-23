import sslFuzzer
import sFunctions
from sFunctions import *
from sslFuzzer import *
from tlslite.api import *
import hashlib
import time
import sys


host = sys.argv[1]
port = sys.argv[2]

sLib = LibSSL(debugFlag = 1)

clientHello = sLib.CreateClientHello("\x01", "", "\x03\x00", chConstGMT, chConstData, "\x00", "\x00\x02", "\x00\x04", "\x01\x00")
sDesc = sLib.TCPConnect(host, int(port))
sLib.SendCTPacket(sDesc, sLib.sslStruct['cHello'])
sLib.ReadServerHello(sDesc)
sLib.ReadServerCertificate(sDesc)
sLib.ReadServerHelloDone(sDesc)
sLib.CreateClientKeyExchange(sDesc)
sLib.SendCTPacket(sDesc, sLib.sslStruct['ckeMessage'])
sDesc.send(cssPkt)
sLib.CreateMasterSecret(sDesc)
sLib.CreateFinishedHash(sDesc)
sLib.CreateKeyBlock(sDesc)
sLib.SendSSLPacket(sDesc, sLib.sslStruct['cFinished'])
sLib.ReadSF(sDesc)
sLib.SendRecordPacket(sDesc, "GET / HTTP/1.0\r\nContent-Length:0\r\n\r\n", 1)
sLib.ReadSSLPacket(sDesc)
