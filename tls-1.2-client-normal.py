from tls1_2API import *
from sslAPI import *
from sFunctions import *
from tlslite.api import *
from config import *
from logger import *
from common import *
from init import *
import socket, sys, random, time, getopt, copy, os

def usage():
	print 	"<program name> \r\n\r\n \
[-h | --help] \r\n \
--host=|-o <host IP> \r\n \
--port=|-p <port number> \r\n \
--config|-c <config file> \r\n \
--log|-l <log file> \r\n \
--ca|-a <CA File + cert file in PEM format> \r\n \
--debug|-d \r\n \
--cipher|-x \r\n \
"

host = port = test_case = rng = value = seq = sof = config_file = cipher_value = log_file = comm = ca_file = cipher = None
spaces = "                 "
debugFlag = 0

try:
	opts, args = getopt.getopt(sys.argv[1:], "ho:p:c:l:a:fdx:", 
		["help", "host=", "port=", "config=", "log=", "ca=", "startonfail=", "debug=", "cipher="])
except getopt.GetoptError, err:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(1)

for o, a in opts:
       	if o in ("-h", "--help"):
	        usage()
		sys.exit()
  	elif o in ("-o", "--host"):
		host = a
	elif o in ("-p", "--port"):
		port = int(a, 10)
	elif o in ("-c", "--config"):
		config_file = a
	elif o in ("-l", "--log"):
		log_file = a
	elif o in ("-a", "--ca"):
		ca_file = a
	elif o in ("-f", "--startonfail"):
		sof = a
	elif o in ("-d", "--debug"):
		debugFlag = 1
	elif o in ("-x", "--cipher"):
		cipher = a
		print cipher
	else:
		print "Invalid arguments supplied"

if cipher == "AES-256-SHA":
	cipher_value = "\x00\x35"

if cipher == "AES-128-SHA":
	cipher_value = "\x00\x2F"

if cipher == None:
	cipher = DEFAULT_CH_CIPHER_SUITES_NAME
	cipher_value = DEFAULT_CH_CIPHER_SUITES_VALUE

if (host == None) or (port == None) or (config_file == None):
	usage()
	sys.exit(2)

#
# set logger and config objects
#
if (log_file == None) or (config_file == None):
	print "Invalid log file/config file specified"
	usage()
	sys.exit(1)

logger = logger(log_file)
if logger.read_error == 1:
	print "Unable to open log file for writing"
	sys.exit(1)

config = config(config_file)
config.parse_and_validate()
if config.read_error == 1:
	logger.toboth("Unable to open config file for reading")
	sys.exit(1)
if config.config_status == CONFIG_INVALID:
	logger.toboth("Config file is having some lines in invalid format, \
please check")
	sys.exit(1)
if config.valid_lines == 0:
	logger.toboth("No valid lines in config file")
	sys.exit(1)

common = common(logger, host, port, config, ca=ca_file, cipher=cipher_value)
ssl_config_obj_list = copy.deepcopy(config.config_obj_list)
sLib = LibTLS(debugFlag, config_obj_list = ssl_config_obj_list, comm = common)
populate_random_numbers(common, sLib)

logger.toboth("starting TLS handshake")
sLib.TCPConnect()
sLib.log("Creating ClientHello")
sLib.CreateClientHello()
sLib.log("Length of ClientHello:%s\n" % \
	str(len(sLib.sslStruct['cHello'])))

sLib.HexStrDisplay("ClientHello Message", 
	Str2HexStr(sLib.sslStruct['cHello']))

sLib.log("Sending packet")
sLib.SendCTPacket()
sLib.log("Reading ServerHello")
sLib.ReadServerHello()
sLib.HexStrDisplay("ServerHello Message Received", 
	Str2HexStr(sLib.sslStruct['sHello']))
sLib.HexStrDisplay("ServerHello Random Bytes",
	Str2HexStr(sLib.sslStruct['sHelloRB']))	

if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)

sLib.log("Reading server Certificate")
sLib.ReadServerCertificate()
if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)
sLib.HexStrDisplay("Server Certificate", 
	Str2HexStr(sLib.sslStruct['sCertificate']))
sLib.HexStrDisplay("Server Certificate CF", 
	Str2HexStr(sLib.sslStruct['sCertificateCF']))
sLib.HexStrDisplay("Fingerprint",Str2HexStr(sLib.x509.getFingerprint()))
logger.tofile("Number of Certificates: " + str(sLib.x509cc.getNumCerts()))
sLib.log("Read ServerCertificate")

sLib.log("Reading ServerHelloDone")
sLib.ReadServerHelloDone()
if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)
sLib.HexStrDisplay("Server HelloDone", 
	Str2HexStr(sLib.sslStruct['sHelloDone']))
sLib.log("Read ServerHelloDone")

sLib.log("Creating client key exchange")
sLib.CreateClientKeyExchange()
sLib.HexStrDisplay("Client KeyExchange Message", 
	Str2HexStr(sLib.sslStruct['ckeMessage']))
sLib.HexStrDisplay("Client Encrypted Pre Master Key", 
	Str2HexStr(sLib.sslStruct['encryptedPMKey']))
sLib.HexStrDisplay("Client ChangeCipherSpec Message", 
	Str2HexStr(cssPkt))		

sLib.log("sending ClientKeyExchange")
sLib.SendCTPacket()

sLib.log("sending CSS packet")
sLib.socket.send(tls12CSSPkt)
if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)

sLib.log("Creating master secret")
sLib.HexStrDisplay("ClientRandom:", 
	Str2HexStr(sLib.sslStruct['cHelloRB']))
sLib.HexStrDisplay("ServerRandom:", 
	Str2HexStr(sLib.sslStruct['sHelloRB']))
sLib.HexStrDisplay("ckePMKey:", Str2HexStr(ckePMKey))

sLib.CreateMasterSecret()

sLib.HexStrDisplay("MasterSecret", 
	Str2HexStr(sLib.sslStruct['masterSecret']))
sLib.log("Created MasterSecret")

sLib.log("Creating finished hash")
sLib.HexStrDisplay("ClientHello", Str2HexStr(sLib.sslStruct['cHello']))
sLib.HexStrDisplay("ServerHello", Str2HexStr(sLib.sslStruct['sHello']))
sLib.HexStrDisplay("Server Certificate", 
	Str2HexStr(sLib.sslStruct['sCertificateCF']))
sLib.HexStrDisplay("Server Hello Done", 
	Str2HexStr(sLib.sslStruct['sHelloDone']))
sLib.HexStrDisplay("Client Key Exchange", 
	Str2HexStr(sLib.sslStruct['ckeMessage']))
sLib.HexStrDisplay("Master Secret", 
	Str2HexStr(sLib.sslStruct['masterSecret']))

sLib.CreateFinishedHash()

sLib.HexStrDisplay("SHA Hash", Str2HexStr(sLib.shaHash))
sLib.HexStrDisplay("ClientFinished Message", 
	Str2HexStr(sLib.sslStruct['cFinished']))
sLib.log("Created Finished Hash")

sLib.log("Creating key block")
sLib.CreateKeyBlock()
sLib.HexStrDisplay("Key Block", Str2HexStr(sLib.sslStruct['keyBlock']))
sLib.HexStrDisplay("wMacPtr", Str2HexStr(sLib.sslStruct['wMacPtr']))
sLib.HexStrDisplay("rMacPtr", Str2HexStr(sLib.sslStruct['rMacPtr']))
sLib.HexStrDisplay("wKeyPtr", Str2HexStr(sLib.sslStruct['wKeyPtr']))
sLib.HexStrDisplay("rKeyPtr", Str2HexStr(sLib.sslStruct['rKeyPtr']))
sLib.HexStrDisplay("wIVPtr", Str2HexStr(sLib.sslStruct['wIVPtr']))
sLib.HexStrDisplay("rIVPtr", Str2HexStr(sLib.sslStruct['rIVPtr']))
sLib.log("Created Key Block")

sLib.log("sending Client Finished")
sLib.SendSSLPacket(sLib.sslStruct['cFinished'], 0, 0)
sLib.log("sent Client Finished")

sLib.log("Reading server finished")
sLib.ReadSF()
sLib.log("Read server finished")
logger.toboth("TLS handshake completed")

req1 = "GET / HTTP/1.1\r\n\r\n"

sLib.log("Sending data")
sLib.HexStrDisplay("Data", Str2HexStr(req1))
sLib.SendRecordPacket(req1, 1)
sLib.log("send data")

sLib.log("Reading SSL packet")
sLib.ReadSSLPacket()
sys.stdout.write("\nData received: \n%s\n" % (sLib.decryptedData))
sLib.log("Read SSL packet")

# sLib.SendSSLPacket(sDesc, sLib.sslStruct['cHello'], 1, 1)
