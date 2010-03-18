from sslFuzzer import *
from sFunctions import *
from tlslite.api import *


host = sys.argv[1]
port = sys.argv[2]

sLib = LibSSL(debugFlag = 1)

clientHello = sLib.CreateClientHello("\x01", "", "\x03\x00", chConstGMT, chConstData, "\x00", "\x00\x02", "\x00\x35", "\x01\x00")
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
HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))
sLib.SendSSLPacket(sDesc, sLib.sslStruct['cFinished'], 0, 0)
HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))
sLib.ReadSF(sDesc)
HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))


xml = '<?xml version="1.0" encoding="utf-8" ?><CIM CIMVERSION="2.0" DTDVERSION="2.0"><MESSAGE ID="4711" PROTOCOLVERSION="1.0"><SIMPLEREQ><IMETHODCALL NAME="EnumerateInstanceNames"><LOCALNAMESPACEPATH><NAMESPACE NAME="root"></NAMESPACE><NAMESPACE NAME="cimv2"></NAMESPACE></LOCALNAMESPACEPATH><IPARAMVALUE NAME="ClassName"><CLASSNAME NAME="CIM_Account"/></IPARAMVALUE></IMETHODCALL></SIMPLEREQ></MESSAGE></CIM>'

req1 = "POST / HTTP/1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1\r\nAuthorization: Basic cm9vdDpjYSRoYzB3\r\nContent-Length:10\r\n\r\n" + xml

print req1
HexStrDisplay("Sending Request", Str2HexStr(req1))
sLib.SendRecordPacket(sDesc, req1, 1)
HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))
sLib.ReadSSLPacket(sDesc)
HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))
sLib.ReadSSLPacket(sDesc)
HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))

#sLib.SendSSLPacket(sDesc, sLib.sslStruct['cHello'], 1, 1)
