#!/usr/bin/python

import os
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
import hashlib
from hashlib import *

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
		self.sslStruct['cHelloRB']	=  chGMT + cHelloRB
		self.sslStruct['chSIDLength'] 	=  chSIDLength
		self.sslStruct['chCipherLength']=  chCipherLength
		self.sslStruct['chCipher'] 	=  chCipher
		self.sslStruct['chCompression'] =  chCompression

		os.system('rm -rf files')
		os.system('mkdir files')

		self.sslStruct['cHello_len'] = len(self.sslStruct['chVersion'] + \
						self.sslStruct['cHelloRB'] + \
						self.sslStruct['chSIDLength'] + \
						self.sslStruct['chCipherLength'] + \
						self.sslStruct['chCipher'] + \
						self.sslStruct['chCompression'])

		if self.sslStruct['chLength'] == "":
			self.sslStruct['chLength'] = Pack3Bytes(self.sslStruct['cHello_len'])

		self.sslStruct['cHello'] = self.sslStruct['chMessage']      + \
					   self.sslStruct['chLength']       + \
					   self.sslStruct['chVersion']      + \
                                           self.sslStruct['cHelloRB']       + \
                                           self.sslStruct['chSIDLength']    + \
					   self.sslStruct['chCipherLength'] + \
					   self.sslStruct['chCipher']       + \
					   self.sslStruct['chCompression']


		HexStrDisplay("chLength", Str2HexStr(self.sslStruct['chLength']))

		if (self.debugFlag == 1):	
			pBanner("Creating ClientHello")
			print "\nLength of ClientHello:" + \
			str(len(self.sslStruct['cHello']))

			HexStrDisplay(	"ClientHello Message Created", 
					Str2HexStr(self.sslStruct['cHello']))
			pBanner("Created ClientHello")

	
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
		pBanner("Reading ServerHello")
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
		pBanner("Read ServerHello")

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
		pBanner("Reading ServerCertificate")
		self.socket = socket
		header = self.socket.recv(5)
		scLen = HexStr2IntVal(header, 3, 4)
		self.sslStruct['scLen'] = scLen
		sCertificate = self.socket.recv(scLen)
		self.sslStruct['sCertificate'] = sCertificate[10:]
		self.sslStruct['sCertificateCF'] = sCertificate

		if (self.debugFlag == 1):
			HexStrDisplay("Server Certificate", 
				Str2HexStr(self.sslStruct['sCertificate']))

		fobject = open("./files/servercrt.pem", 'w')
		fobject.write("-----BEGIN CERTIFICATE-----\n")
		output = base64.b64encode(self.sslStruct['sCertificate'])
		fobject.write(output)
		fobject.write("\n-----END CERTIFICATE-----\n")
		fobject.close()

		sCert = open("./files/servercrt.pem").read()
		x509 = X509()
		cert = x509.parse(sCert)

		x509cc = X509CertChain([x509])
		HexStrDisplay("Fingerprint",Str2HexStr(x509.getFingerprint()))
		print "\nNumber of Certificates: " + str(x509cc.getNumCerts())
		pBanner("Read ServerCertificate")

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
		pBanner("Reading ServerHelloDone")
		self.socket = socket
		header = self.socket.recv(5)
		sHelloDone = self.socket.recv(4)
		self.sslStruct['sHelloDone'] = sHelloDone

		if (self.debugFlag == 1):
			HexStrDisplay("Server HelloDone", 
				Str2HexStr(self.sslStruct['sHelloDone']))
		pBanner("Read ServerHelloDone")

###############################################################################
#
# SendCT --
#
# 			Function to send a cleartext ssl handshake
#			message
#
# Results:
#			1. SSL cleartext record layer header is added
#			2. clear text handshake message is sent
#
# Side Effects:
#			None
###############################################################################

	def SendCTPacket(self, socket, hsMsg):
		pBanner("Sending CT Packet")
		self.socket = socket
		recMsg = 	sslRecHeaderDeafult  + \
				Pack2Bytes(len(hsMsg))
	
		totMsg = recMsg + hsMsg
		
		print "\nLength of HS Message: ", str(len(hsMsg))
		print "\nLength of Total Message: ", str(len(totMsg))
		HexStrDisplay("HS Message CT:", Str2HexStr(hsMsg))
		HexStrDisplay("Total Message CT:", Str2HexStr(totMsg))

		self.socket.send(totMsg)
		pBanner("Sent CT Packet")

##############################################################################
#
# SendSSLPacket --
#
# 			Function to send an SSL handshake packet after adding
#			record layer headers
#
# Results:
#			1. Takes SSL Handshake message as input
#			2. Adds SSL record layer headers to it
#			3. Sends the packet to Server
#
# Side Effects:
#			None
###############################################################################
	def SendSSLPacket(self, socket, hsMsg):
			pBanner("Sending SSL Packet")
			import socket
			rec = hsMsg
			recLen = len(hsMsg)
			HexStrDisplay("Record Length", Str2HexStr(Pack2Bytes(recLen)))
			HexStrDisplay("Record", Str2HexStr(rec))
			seqNum = 0
			seqNumUnsignedLongLong = pack('>Q', seqNum)
			iHash = pack('b', 22)
			iHash1 = Pack2Bytes(recLen)

			m = md5()
			m.update(self.sslStruct['wMacPtr'])
			m.update(pad1MD5)
			m.update(seqNumUnsignedLongLong + iHash + iHash1)
			m.update(rec)
			mInt = m.digest()
	
			m1 = md5()
			m1.update(self.sslStruct['wMacPtr'])
			m1.update(pad2MD5)
			m1.update(mInt)
			mFin = m1.digest()
	
			HexStrDisplay("Intermediate MAC", 
						Str2HexStr(mInt))
	
			HexStrDisplay("Final MAC", Str2HexStr(mFin))
	
			self.sslStruct['recordPlusMAC'] = rec + mFin
			HexStrDisplay("Record + MAC", 
				      Str2HexStr(self.sslStruct['recordPlusMAC']))
	
			global e

			e = tlslite.utils.OpenSSL_RC4.new(self.sslStruct['wKeyPtr'])
			encryptedData = e.encrypt(self.sslStruct['recordPlusMAC'])
			
			HexStrDisplay("Encrypted Record + MAC", 
					Str2HexStr(encryptedData))
	
			packLen = len(encryptedData)
			self.sslStruct['encryptedRecordPlusMAC'] = sslRecHeaderDeafult + \
					Pack2Bytes(packLen) + encryptedData

			HexStrDisplay("Packet Sent", 
			Str2HexStr(self.sslStruct['encryptedRecordPlusMAC']))
		
			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])
			pBanner("Sent SSL Packet")

##############################################################################
#
# SendRecordPacket --
#
# 			Function to send an SSL Application Data after adding
#			record layer headers
#
# Results:
#			1. Takes SSL record message as input
#			2. Adds SSL record layer headers to it
#			3. Sends the packet to Server
#
# Side Effects:
#			None
###############################################################################
	def SendRecordPacket(self, socket, recMsg, seq):
			pBanner("Sending SSL Record Packet")
			import socket
			rec = recMsg
			recLen = len(recMsg)
			HexStrDisplay("Record Length", Str2HexStr(Pack2Bytes(recLen)))
			HexStrDisplay("Record", Str2HexStr(rec))
			seqNum = seq
			seqNumUnsignedLongLong = pack('>Q', seqNum)
			iHash = pack('b', 23)
			iHash1 = Pack2Bytes(recLen)

			m = md5()
			m.update(self.sslStruct['wMacPtr'])
			m.update(pad1MD5)
			m.update(seqNumUnsignedLongLong + iHash + iHash1)
			m.update(rec)
			mInt = m.digest()
	
			m1 = md5()
			m1.update(self.sslStruct['wMacPtr'])
			m1.update(pad2MD5)
			m1.update(mInt)
			mFin = m1.digest()
	
			HexStrDisplay("Intermediate MAC", 
						Str2HexStr(mInt))
	
			HexStrDisplay("Final MAC", Str2HexStr(mFin))
	
			self.sslStruct['recordPlusMAC'] = rec + mFin
			HexStrDisplay("Record + MAC", 
				      Str2HexStr(self.sslStruct['recordPlusMAC']))
	
			HexStrDisplay("wKeyPtr", 
				      Str2HexStr(self.sslStruct['wKeyPtr']))
			
			encryptedData = e.encrypt(self.sslStruct['recordPlusMAC'])
			
			HexStrDisplay("Encrypted Record + MAC", 
					Str2HexStr(encryptedData))
	
			packLen = len(encryptedData)
			self.sslStruct['encryptedRecordPlusMAC'] = sslAppHeaderDefault + \
					Pack2Bytes(packLen) + encryptedData

			HexStrDisplay("Packet Sent", 
			Str2HexStr(self.sslStruct['encryptedRecordPlusMAC']))
		
			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])
			pBanner("Sent SSL Record Packet")

##############################################################################
#
# ReadCTPacket --
#
# 			Function to read cleartext response from server
#
# Results:
#			1. Reads cleartext response from server
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def ReadCTPacket(self, socket):
			pBanner("Reading CT Packet")
			socket = self.socket
			header = self.socket.recv(5)
			recLen = HexStr2IntVal(header, 3, 4)
			data = self.socket.recv(recLen)
			print str(data)
			pBanner("Read CT Packet")			

##############################################################################
#
# ReadSSLPacket --
#
# 			Function to read response from server
#
# Results:
#			1. Reads response from server
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def ReadSSLPacket(self, socket):
			pBanner("Reading SSL Packet")
			header = self.socket.recv(5)
			HexStrDisplay("data", Str2HexStr(header))
			recLen = HexStr2IntVal(header, 3, 4)
			print "Record Length: " + str(recLen)
			data = self.socket.recv(recLen)

			decrypt = f.decrypt(data)

			print decrypt
			pBanner("Read SSL Packet")			

##############################################################################
#
# ReadSF --
#
# 			Function to read ServerFinished Message from server
#
# Results:
#			1. Reads ChangeCipherSpec and ServerFinished Message from server
#			3. Stores necessary values as part of sslStruct
#
# Side Effects:
#			None
###############################################################################
	def ReadSF(self, socket):
			pBanner("Reading ServerFinished from server")
			socket = self.socket
			header = self.socket.recv(5)
			CFLen = HexStr2IntVal(header, 3, 4)
			if CFLen == 1:
				print "\nINFO: Received Server Change Cipher Spec"
				cssSer = self.socket.recv(1)
			header = self.socket.recv(5)
			CFLen = HexStr2IntVal(header, 3, 4)
			print "\nINFO: Received ServerFinished Message of Length: " + str(CFLen)
			CFMessage = self.socket.recv(CFLen)
			if (CFMessage):
				HexStrDisplay("\nINFO: Finished Read from Server",
					Str2HexStr(CFMessage))
			global f
			f = tlslite.utils.OpenSSL_RC4.new(self.sslStruct['rKeyPtr'])
			decryptedCF = f.decrypt(CFMessage)

			HexStrDisplay("\nINFO: Decrypted Finished Message from Server", 
					Str2HexStr(decryptedCF))
			pBanner("Read ServerFinished from server")			

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
		pBanner("Creating ClientKeyExchange")

		sCert = open("./files/servercrt.pem").read()
		x509 = X509()
		cert = x509.parse(sCert)

		x509cc = X509CertChain([x509])
		ckeArray = array ( 'B', ckePMKey)
		encData = cert.publicKey.encrypt(ckeArray)
		encDataStr = encData.tostring()
		self.sslStruct['encryptedPMKey'] = encDataStr
		self.sslStruct['encryptedPMKey_len'] = len(self.sslStruct['encryptedPMKey'])


		self.sslStruct['ckeMessage'] = 	ckeMsgHdr + \
			Pack3Bytes(self.sslStruct['encryptedPMKey_len']) + \
			self.sslStruct['encryptedPMKey']

		if (self.debugFlag == 1):
			HexStrDisplay("Client KeyExchange Message", 
				Str2HexStr(self.sslStruct['ckeMessage']))
			HexStrDisplay("Client Encrypted Pre Master Key", 
				Str2HexStr(self.sslStruct['encryptedPMKey']))
			HexStrDisplay("Client ChangeCipherSpec Message", 
				Str2HexStr(cssPkt))			
		self.encrypted = 0	
		pBanner("Created ClientKeyExchange")

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
		pBanner("Creating MasterSecret")
		self.socket = socket

		HexStrDisplay("ClientRandom:", 
				Str2HexStr(self.sslStruct['cHelloRB']))
		HexStrDisplay("ServerRandom:", 
				Str2HexStr(self.sslStruct['sHelloRB']))
		HexStrDisplay("ckePMKey:", Str2HexStr(ckePMKey))

		s1 = sha1()
		s1.update('A')
		s1.update(ckePMKey)
		s1.update(self.sslStruct['cHelloRB'])
		s1.update(self.sslStruct['sHelloRB'])
		s1D = s1.digest()

		m1 = md5()
		m1.update(ckePMKey)
		m1.update(s1D)
		m1D = m1.digest()

		s2 = sha1()
		s2.update('BB')
		s2.update(ckePMKey)
		s2.update(self.sslStruct['cHelloRB'])
		s2.update(self.sslStruct['sHelloRB'])
		s2D = s2.digest()

		m2 = md5()
		m2.update(ckePMKey)
		m2.update(s2D)
		m2D = m2.digest()

		s3 = sha1()
		s3.update('CCC')
		s3.update(ckePMKey)
		s3.update(self.sslStruct['cHelloRB'])
		s3.update(self.sslStruct['sHelloRB'])
		s3D = s3.digest()

		m3 = md5()
		m3.update(ckePMKey)
		m3.update(s3D)
		m3D = m3.digest()

		self.sslStruct['masterSecret'] = m1D + m2D + m3D
		HexStrDisplay("MasterSecret", 
				Str2HexStr(self.sslStruct['masterSecret']))

		pBanner("Created MasterSecret")


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
		pBanner("Creating Finished Hash")
	

		HexStrDisplay("ClientHello", Str2HexStr(self.sslStruct['cHello']))
		HexStrDisplay("ServerHello", Str2HexStr(self.sslStruct['sHello']))
		HexStrDisplay("Server Certificate", 
				Str2HexStr(self.sslStruct['sCertificateCF']))
		HexStrDisplay("Server Hello Done", 
				Str2HexStr(self.sslStruct['sHelloDone']))
		HexStrDisplay("Client Key Exchange", 
				Str2HexStr(self.sslStruct['ckeMessage']))
		HexStrDisplay("Master Secret", 
				Str2HexStr(self.sslStruct['masterSecret']))

		self.socket = socket

		m1 = md5()
		m1.update(self.sslStruct['cHello'])
		m1.update(self.sslStruct['sHello'])
		m1.update(self.sslStruct['sCertificateCF'])
		m1.update(self.sslStruct['sHelloDone'])
		m1.update(self.sslStruct['ckeMessage'])
		m1.update("CLNT")
		m1.update(self.sslStruct['masterSecret'])
		m1.update(pad1MD5)

	
		m2 = md5()
		m2.update(self.sslStruct['masterSecret'])
		m2.update(pad2MD5)
		m2.update(m1.digest())
		md5Hash = m2.digest()

		s1 = sha1()
		s1.update(self.sslStruct['cHello'])
		s1.update(self.sslStruct['sHello'])
		s1.update(self.sslStruct['sCertificateCF'])
		s1.update(self.sslStruct['sHelloDone'])
		s1.update(self.sslStruct['ckeMessage'])
		s1.update("CLNT")
		s1.update(self.sslStruct['masterSecret'])
		s1.update(pad1SHA)
		
		s2 = sha1()
		s2.update(self.sslStruct['masterSecret'])
		s2.update(pad2SHA)
		s2.update(s1.digest())

		shaHash = s2.digest()

		HexStrDisplay("MD5 Hash", Str2HexStr(md5Hash))
		HexStrDisplay("SHA Hash", Str2HexStr(shaHash))

		self.sslStruct['cFinished'] = "\x14\x00\x00\x24" + \
					md5Hash + shaHash
		HexStrDisplay("ClientFinished Message", 
			Str2HexStr(self.sslStruct['cFinished']))
		pBanner("Created Finished Hash")

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
		pBanner("Creating Key Block")
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


		for iter in range(0, self.sslStruct['keyIter']):
			s = sha1()
			m = md5()

			s.update(chr( ord('A') + iter) * (iter + 1))
			s.update(self.sslStruct['masterSecret'])
			s.update(self.sslStruct['sHelloRB'])
			s.update(self.sslStruct['cHelloRB'])
			sInt = s.digest()

			m.update(self.sslStruct['masterSecret'])
			m.update(sInt)
			mFin = m.digest()
			self.sslStruct['keyBlock'] = 	self.sslStruct['keyBlock'] + \
							mFin


		HexStrDisplay("Key Block", Str2HexStr(self.sslStruct['keyBlock']))
	
		self.sslStruct['wMacPtr'] = self.sslStruct['keyBlock'][0:16]
		self.sslStruct['rMacPtr'] = self.sslStruct['keyBlock'][16:32]
		self.sslStruct['wKeyPtr'] = self.sslStruct['keyBlock'][32:48]
		self.sslStruct['rKeyPtr'] = self.sslStruct['keyBlock'][48:64]
		self.sslStruct['wIVPtr'] = self.sslStruct['keyBlock'][64:72]
		self.sslStruct['rIVPtr'] = self.sslStruct['keyBlock'][72:80]


		HexStrDisplay("wMacPtr", Str2HexStr(self.sslStruct['wMacPtr']))
		HexStrDisplay("rMacPtr", Str2HexStr(self.sslStruct['rMacPtr']))
		HexStrDisplay("wKeyPtr", Str2HexStr(self.sslStruct['wKeyPtr']))
		HexStrDisplay("rKeyPtr", Str2HexStr(self.sslStruct['rKeyPtr']))
		HexStrDisplay("wIVPtr", Str2HexStr(self.sslStruct['wIVPtr']))
		HexStrDisplay("rIVPtr", Str2HexStr(self.sslStruct['rIVPtr']))
		pBanner("Created Key Block")


