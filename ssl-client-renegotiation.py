from sslFuzzer import *
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
"

host = port = test_case = rng = value = seq = sof = config_file = log_file = comm = None
spaces = "                 "

try:
	opts, args = getopt.getopt(sys.argv[1:], "ho:p:c:l:f", 
		["help", "host=", "port=", "config=", "log=", "startonfail="])
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
	elif o in ("-f", "--startonfail"):
		sof = a
	else:
		print "Invalid arguments supplied"

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

common = common(logger, host, port, config)
ssl_config_obj_list = copy.deepcopy(config.config_obj_list)
sLib = LibSSL(debugFlag = 0, config_obj_list = ssl_config_obj_list, comm = common)
populate_random_numbers(common, sLib)

sLib.TCPConnect()
sLib.CreateClientHello()
sLib.SendCTPacket()
sLib.ReadServerHello()
if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)

sLib.ReadServerCertificate()
if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)

sLib.ReadServerHelloDone()
if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)

sLib.CreateClientKeyExchange()
sLib.SendCTPacket()
sLib.socket.send(cssPkt)
if sLib.opn == 1:
	logger.toboth("Server did not respond properly")
	sys.exit(1)
sLib.CreateMasterSecret()
sLib.CreateFinishedHash()
sLib.CreateKeyBlock()
if sLib.debugFlag == 1:
	HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
	HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))
sLib.SendSSLPacket(sLib.sslStruct['cFinished'], 0, 0)
if sLib.debugFlag == 1:
	HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
	HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))
sLib.ReadSF()
if sLib.debugFlag == 1:
	HexStrDisplay("WIV ", Str2HexStr(sLib.sslStruct['wIVPtr']))
	HexStrDisplay("RIV ", Str2HexStr(sLib.sslStruct['rIVPtr']))

sLib.SendSSLPacket(sLib.sslStruct['cHello'], 1, 1)
try:
	sLib.ReadSSLPacket()
	if sLib.decryptedData[0] == "\x02":
		logger.toboth("Server does not support unsafe legacy re-negotiation")
except:
	logger.toboth("server has not responded with an alert or re-negotiation handshake")

sys.exit(1)
