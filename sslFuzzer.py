#!/usr/bin/python

import sys
import socket
import sFunctions
import string
import struct
from struct import *
from sFunctions import *
import constants
from constants import *
from tlslite.api import *
import tlslite
import base64
from Crypto.Cipher import AES
from array import *

###############################################################################
#
# LibSSL --
#
# 			SSL Class for Fuzzer
#
###############################################################################

###############################################################################
#
# Handshake Messages (after removing Record Layer Header till CKEMessage) are:
#
# 					self.sslStruct['cHello']
#					self.sslStruct['sHello']
#					self.sslStruct['sCertificate']
#					self.sslStruct['sHelloDone']
#					self.sslStruct['ckeMessage']
#
###############################################################################


class LibSSL:
#
# Constructor
#
	def __init__(self, debugFlag = 0):
		self.sslStruct = {}
		self.clientHello = None
		self.debugFlag = debugFlag

###############################################################################
#
# TCPConnect --
#
# 			Establishes a TCP connection and returns 
#			the socket descriptor
#
# Results:
#			Establishes a TCP connection to a server:port 
#			and returns socket
#
# Side Effects:
#			None
###############################################################################
	def TCPConnect(self, host, port):
		self.socketDesc = socket.socket(socket.AF_INET, 
					socket.SOCK_STREAM)
		self.socketDesc.connect((host, port))
		return self.socketDesc

###############################################################################
#
# CreateClientHello --
#
# 			Function to create a SSL Client Hello packet
#
# Results:
#			1. Creates a customized SSL Client Hello packet
#
# Side Effects:
#			None
###############################################################################
	def CreateClientHello(self, chMessage = chConstMessage, 
                         chLength=chConstLength, chVersion = chConstVersion, 
                         chGMT=chConstGMT, cHelloRB=chConstData, 
			 chSIDLength=chConstSIDLength, 
                         chCipherLength=chConstCipherLength, 
                         chCipher=chConstCipher,
			 chCompression=chConstCompression):
		self.sslStruct['chMessage'] 	=  chMessage
		self.sslStruct['chLength'] 	=  chLength
		self.sslStruct['chVersion'] 	=  chVersion
		self.sslStruct['chGMT'] 	=  chGMT
		self.sslStruct['cHelloRB']	=  cHelloRB
		self.sslStruct['chSIDLength'] 	=  chSIDLength
		self.sslStruct['chCipherLength']=  chCipherLength
		self.sslStruct['chCipher'] 	=  chCipher
		self.sslStruct['chCompression'] =  chCompression


		self.sslStruct['cHello'] = self.sslStruct['chMessage']      + \
					   self.sslStruct['chLength']       + \
					   self.sslStruct['chVersion']      + \
	                                   self.sslStruct['chGMT']          + \
                                           self.sslStruct['cHelloRB']       + \
                                           self.sslStruct['chSIDLength']    + \
					   self.sslStruct['chCipherLength'] + \
					   self.sslStruct['chCipher']       + \
					   self.sslStruct['chCompression']

		if (self.debugFlag == 1):		
			HexStrDisplay(	"ClientHello Message Created", 
					Str2HexStr(self.sslStruct['cHello']))



	
###############################################################################
#
# ReadServerHello --
#
# 			Function to read a ServerHello 
#			Message sent by SSL Server
#
# Results:
#			1. Reads ServerHello Message sent by server 
#			2. Interprets its details
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def ReadServerHello(self, socket):
		self.socket = socket
		header = self.socket.recv(5)
		shLen = HexStr2IntVal(header, 3, 4)
		self.sslStruct['shLen'] = shLen
		sHello = self.socket.recv(shLen)

		self.sslStruct['sHello'] = sHello
		self.sslStruct['sHelloRB'] = sHello[6:-4]

		if (self.debugFlag == 1):		
			HexStrDisplay(	"ServerHello Message Received", 
					Str2HexStr(self.sslStruct['sHello']))
			HexStrDisplay(  "ServerHello Random Bytes",
					Str2HexStr(self.sslStruct['sHelloRB']))		

###############################################################################
#
# ReadServerCertificate --
#
# 			Function to read a ServerCertificate Message 
#			sent by SSL Server
#
# Results:
#			1. Reads ServerCertificate Message sent by server 
#			2. Interprets its details
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def ReadServerCertificate(self, socket):
		self.socket = socket
		header = self.socket.recv(5)
		scLen = HexStr2IntVal(header, 3, 4)
		self.sslStruct['scLen'] = scLen
		sCertificate = self.socket.recv(scLen)
		self.sslStruct['sCertificate'] = sCertificate[10:]

		if (self.debugFlag == 1):
			HexStrDisplay("Server Certificate", 
				Str2HexStr(self.sslStruct['sCertificate']))

		fobject = open("./servercrt.pem", 'w')
		fobject.write("-----BEGIN CERTIFICATE-----\n")
		output = base64.b64encode(self.sslStruct['sCertificate'])
		fobject.write(output)
		fobject.write("\n-----END CERTIFICATE-----\n")
		fobject.close()

		sCert = open("./servercrt.pem").read()
		x509 = X509()
		cert = x509.parse(sCert)

		x509cc = X509CertChain([x509])
		HexStrDisplay("Fingerprint",Str2HexStr(x509.getFingerprint()))
		print "\nNumber of Certificates: " + str(x509cc.getNumCerts())
		ckeArray = array ( 'B', ckePMKey)
		encData = cert.publicKey.encrypt(ckeArray)
		encDataStr = encData.tostring()
		self.sslStruct['encryptedPMKey'] = encDataStr

###############################################################################
#
# ReadServerHelloDone --
#
# 			Function to read a ServerHelloDone 
#			Message sent by SSL Server
#
# Results:
#			1. Reads ServerHelloDone Message sent by server 
#			2. Interprets its details
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def ReadServerHelloDone(self, socket):
		self.socket = socket
		header = self.socket.recv(5)
		sHelloDone = self.socket.recv(4)
		self.sslStruct['sHelloDone'] = sHelloDone

		if (self.debugFlag == 1):
			HexStrDisplay("Server HelloDone", 
				Str2HexStr(self.sslStruct['sHelloDone']))

###############################################################################
#
# SendSSLPacket --
#
# 			Function to send a encrypted or cleartext ssl handshake
#			message
#
# Results:
#			1. If self.encrypted = 0, clear text handshake message
#                          is sent
#			2. else, encrypted handshake message is sent
#
# Side Effects:
#			None
###############################################################################

	def SendCTPacket(self, socket, hsMsg):
		self.socket = socket
		recMsg = 	sslRecHeaderDeafult  + \
				Pack2Bytes(len(hsMsg))
	
		totMsg = recMsg + hsMsg
		self.socket.send(totMsg)

	def SendSSLPacket(self, socket, hsMsg):
			import M2Crypto
			import md5
			import sha
			import socket
			rec = hsMsg
			recLen = len(hsMsg)

			seqNum = 0
			seqNumUnsignedLongLong = pack('>Q', seqNum)

			iHash = pack('h', 22)
			iHash1 = (recLen & 0xff00) >> 8
			iHash2 = (recLen & 0xff)
	
			m = md5.new()
			m.update(self.sslStruct['wMacPtr'])
			m.update(pad1MD5)
			m.update(seqNumUnsignedLongLong)
			m.update(str(iHash) + str(iHash1) + str(iHash2))
			m.update(rec)
	
			m1 = md5.new()
			m1.update(self.sslStruct['wMacPtr'])
			m1.update(pad2MD5)
			m1.update(m1.digest())
	
			HexStrDisplay("Intermediate MAC", 
						Str2HexStr(m.digest()))
	
			HexStrDisplay("Final MAC", Str2HexStr(m1.digest()))
	
			self.sslStruct['recordPlusMAC'] = rec + m1.digest()
			HexStrDisplay("Record + MAC", 
				      Str2HexStr(self.sslStruct['recordPlusMAC']))
	
			e = M2Crypto.RC4.RC4()
			e.set_key(self.sslStruct['wKeyPtr'])
			encryptedData = e.update(self.sslStruct['recordPlusMAC'])
			
			HexStrDisplay("Encrypted Record + MAC", 
					Str2HexStr(encryptedData))
	
			packLen = len(encryptedData)
			self.sslStruct['encryptedRecordPlusMAC'] = sslRecHeaderDeafult + Pack2Bytes(packLen) + encryptedData
		
			self.socket.send(self.sslStruct['encryptedRecordPlusMAC'])

##############################################################################
#
# CreateClientKeyExchange --
#
# 			Function to create a ClientKeyExchange message
#
# Results:
#			1. Creates ClientKeyExchange Message
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def CreateClientKeyExchange(self, socket):
		self.socket = socket
		self.sslStruct['cCert'] = cCertMsg

		self.sslStruct['ckeMessage'] = 	ckeMsgHdr + '\x00\x00\x80' + \
						self.sslStruct['encryptedPMKey']

		if (self.debugFlag == 1):
			HexStrDisplay("Client KeyExchange Message", 
				Str2HexStr(self.sslStruct['ckeMessage']))
			HexStrDisplay("Client Encrypted Pre Master Key", 
				Str2HexStr(self.sslStruct['encryptedPMKey']))
			HexStrDisplay("Client ChangeCipherSpec Message", 
				Str2HexStr(cssPkt))			
		self.encrypted = 1			

##############################################################################
#
# CreateMasterSecret --
#
# 			Function to create a MasterSecret
#
# Results:
#			1. Creates MasterSecret
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################

#
# master_secret = MD5(premaster_secret + SHA('A' + client_random + 
#		  server_random + premaster_secret)) +
#		  MD5(premaster_secret + SHA('BB' + client_random + 
#		  server_random + premaster_secret)) +
#		  MD5(premaster_secret + SHA('CCC' + client_random + 
#		  server_random + premaster_secret))
#
#

	def CreateMasterSecret(self, socket):
		import md5
		import sha
		self.socket = socket


		s1 = sha.new()

		s1.update('A')
		s1.update(self.sslStruct['cHelloRB'])
		s1.update(self.sslStruct['sHelloRB'])
		s1.update(ckePMKey)

		HexStrDisplay("First SHA1 Hash", Str2HexStr(s1.digest()))
		m1 = md5.new()
		m1.update(ckePMKey)
		m1.update(Str2HexStr(s1.digest()))

		s2 = sha.new()
		s2.update('BB')
		s2.update(self.sslStruct['cHelloRB'])
		s2.update(self.sslStruct['sHelloRB'])
		s2.update(ckePMKey)

		HexStrDisplay("Second SHA1 Hash", Str2HexStr(s2.digest()))
		m2 = md5.new()
		m2.update(ckePMKey)
		m2.update(s2.digest())
		
		s3 = sha.new()
		s3.update('CCC')
		s3.update(self.sslStruct['cHelloRB'])
		s3.update(self.sslStruct['sHelloRB'])
		s3.update(ckePMKey)

		HexStrDisplay("Third SHA1 Hash", Str2HexStr(s3.digest()))
		m3 = md5.new()
		m3.update(ckePMKey)
		m3.update(s3.digest())

		self.sslStruct['masterSecret'] = m1.digest() + m2.digest() \
						+ m3.digest()
		HexStrDisplay("MasterSecret", 
				Str2HexStr(self.sslStruct['masterSecret']))


##############################################################################
#
# CreateFinishedHash --
#
# 			Function to create a ClientFinished MD5 and SHA Hashes
#
# Results:
#			1. Creates ClientFinished MD5 and SHA Hashes
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################

#
#   ClientFinishedMessage = md5_hash + sha1_Hash
#
#    			    md5_hash = MD5(master_secret + pad2md5 + 
#			    MD5(handshake_messages + Sender + master_secret + 
#			    pad1md5));
#			
#			    sha1_hash =  SHA(master_secret + pad2sha +
#			    SHA(handshake_messages + Sender + master_secret + 
#			    pad1sha));
#
	def CreateFinishedHash(self, socket):
		import md5
		import sha
	
		self.socket = socket

		m1 = md5.new()
		m1.update(self.sslStruct['cHello'])
		m1.update(self.sslStruct['sHello'])
		m1.update(self.sslStruct['sCertificate'])
		m1.update(self.sslStruct['sHelloDone'])
		m1.update(self.sslStruct['ckeMessage'])
		m1.update("\x43\x4c\x4e\x54")
		m1.update(self.sslStruct['masterSecret'])
		m1.update(pad1MD5)
		
		m2 = md5.new()
		m2.update(self.sslStruct['masterSecret'])
		m2.update(pad2MD5)
		m2.update(m1.digest())
		md5Hash = m2.digest()

		s1 = sha.new()
		s1.update(self.sslStruct['cHello'])
		s1.update(self.sslStruct['sHello'])
		s1.update(self.sslStruct['sCertificate'])
		s1.update(self.sslStruct['sHelloDone'])
		s1.update(self.sslStruct['ckeMessage'])
		s1.update("\x43\x4c\x4e\x54")
		s1.update(self.sslStruct['masterSecret'])
		s1.update(pad1MD5)
		
		s2 = sha.new()
		s2.update(self.sslStruct['masterSecret'])
		s2.update(pad2MD5)
		s2.update(s1.digest())

		shaHash = s2.digest()


		HexStrDisplay("MD5 Hash", Str2HexStr(md5Hash))
		HexStrDisplay("SHA Hash", Str2HexStr(shaHash))

		self.sslStruct['cFinished'] = md5Hash + shaHash
		HexStrDisplay("ClientFinished Message", 
			Str2HexStr(self.sslStruct['cFinished']))

##############################################################################
#
# CreateKeyBlock --
#
# 			Function to create a Key Block
#
# Results:
#			1. Creates a Key Block
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################

# 
# key_block =
#	  MD5(master_secret + SHA('A' + master_secret + ServerHello.random +
#		  ClientHello.random)) +
#	  MD5(master_secret + SHA('BB' + master_secret + ServerHello.random +
#		  ClientHello.random)) +
#	  MD5(master_secret + SHA('CCC' + master_secret + ServerHello.random +
#		  ClientHello.random)) + [...];
#

	def CreateKeyBlock(self, socket):
		import md5
		import sha
		self.socket = socket

		self.sslStruct['digLen'] = 16
		self.sslStruct['keyBits'] = 128
		self.sslStruct['blockBits'] = 0
		self.sslStruct['ivSize'] = 0
		self.sslStruct['macSize'] = self.sslStruct['digLen']
		self.sslStruct['keySize'] = self.sslStruct['keyBits'] / 8
		self.sslStruct['writeSeq'] = 0
		self.sslStruct['readSeq'] = 0
		self.sslStruct['reqKeyLen'] = 	2 * self.sslStruct['macSize'] + \
						2 * self.sslStruct['keySize'] + \
						2 * self.sslStruct['ivSize']
		self.sslStruct['keyIter'] = 9
		self.sslStruct['keyBlock'] = ""
		s = sha.new()
		m = md5.new()
		for iter in range(0, self.sslStruct['keyIter']):
			s.update(chr( ord('A') + iter) * (iter + 1))
			s.update(self.sslStruct['masterSecret'])
			s.update(self.sslStruct['sHelloRB'])
			s.update(chConstData)

			m.update(self.sslStruct['masterSecret'])
			m.update(s.digest())
			self.sslStruct['keyBlock'] = 	self.sslStruct['keyBlock'] + \
							m.digest()

		HexStrDisplay("Key Block", Str2HexStr(self.sslStruct['keyBlock']))
	
		self.sslStruct['wMacPtr'] = self.sslStruct['keyBlock'][0:16]
		self.sslStruct['rMacPtr'] = self.sslStruct['keyBlock'][16:32]
		self.sslStruct['wKeyPtr'] = self.sslStruct['keyBlock'][32:48]
		self.sslStruct['wKeyPtr'] = self.sslStruct['keyBlock'][48:64]
		self.sslStruct['wIVPtr'] = self.sslStruct['keyBlock'][64:80]
		self.sslStruct['rIVPtr'] = self.sslStruct['keyBlock'][80:96]


		HexStrDisplay("wMacPtr", Str2HexStr(self.sslStruct['wMacPtr']))
		HexStrDisplay("rMacPtr", Str2HexStr(self.sslStruct['rMacPtr']))
		HexStrDisplay("wKeyPtr", Str2HexStr(self.sslStruct['wKeyPtr']))
		HexStrDisplay("rKeyPtr", Str2HexStr(self.sslStruct['wKeyPtr']))
		HexStrDisplay("wIVPtr", Str2HexStr(self.sslStruct['wIVPtr']))
		HexStrDisplay("rIVPtr", Str2HexStr(self.sslStruct['rIVPtr']))


