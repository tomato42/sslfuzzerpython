from sslFuzzer import *
from sFunctions import *
from tlslite.api import *


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
sLib.SendSSLPacket(sDesc, sLib.sslStruct['cFinished'], 0, 0)
sLib.ReadSF(sDesc)

#req1 = "GET /folder?dcPath=ha-datacenter HTTP/1.1\r\nAuthorization: Basic cm9vdDpjYSRoYzB3\r\nContent-Length:0\r\n\r\n"
#print "Sending Request:\n" + Str2HexStr(req1) + "\n"

#sLib.SendRecordPacket(sDesc, sLib.sslStruct['cHello'], 1)
#sLib.ReadSSLPacket(sDesc)

sLib.SendSSLPacket(sDesc, sLib.sslStruct['cHello'], 1, 1)
