import sslFuzzer
import sFunctions
from sFunctions import *
from sslFuzzer import *

host = sys.argv[1]
port = sys.argv[2]

sLib = LibSSL(debugFlag = 0)

print "Server Accepts the following Ciphers : "

for cipherHex in range(0x00, 0xff):
	cipherStr = Pack2Bytes(cipherHex)
	clientHello = sLib.CreateClientHello(chCipher=cipherStr)
	sDesc = sLib.TCPConnect(host, int(port))
	sDesc.send(clientHello)
	sLib.ReadServerHello(sDesc)
	try:
		value = Str2HexStr(sLib.sslStruct['sHello'][4])
	except IndexError:
			continue
	try:
		cipherName = CipherList[Str2HexStr(cipherStr)]
	except KeyError:
			continue
			print "Unknown Cipher" + Str2HexStr(cipherStr)
	print cipherName

