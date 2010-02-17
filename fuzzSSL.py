import sslFuzzer
import sFunctions
from sFunctions import *
from sslFuzzer import *
from tlslite.api import *
import hashlib
import time


host = sys.argv[1]
port = sys.argv[2]

sLib = LibSSL(debugFlag = 1)

clientHello = sLib.CreateClientHello()
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

#sLib.SendCTPacket(sDesc, sLib.sslStruct['cHello'])


