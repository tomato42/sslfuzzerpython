#!/usr/bin/python

import os, sys, socket, string, struct, base64, hashlib, copy, random

from struct import *
from sFunctions import *
from constants import *
import tlslite
from tlslite.api import *
from Crypto.Cipher import AES
from array import *
from hashlib import *

global enc_hs_with_reneg
global enc_hs_no_reneg
global enc_rec
global dec_rec
global dec_hs

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
	def __init__(self, debugFlag = 0, config_obj_list = None, comm = None):
		self.sslStruct = {}
		self.comm = comm
		self.config_obj_list = config_obj_list
		self.clientHello = None
		self.debugFlag = debugFlag
		self.socket = None
		self.sslHandshake = None
		self.sslRecord = None
		self.opn = 0
		self.cipher = self.comm.cipher

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
	def TCPConnect(self):
		self.socket = socket.socket(socket.AF_INET, 
					socket.SOCK_STREAM)
		self.socket.connect((self.comm.host, self.comm.port))


	#
	# get all keys of the hash
	#
	def get_keys(self):
		return self.config_hash.keys()

	#
	# get all values in the hash
	#
	def get_values(self):
		return self.config_hash.values()

	#
	# payload elements in the config_hash are of the form:
	#     
	#       <key> = <value> : <type>
        #
        #         where <key> is the name of the field
        #               <value> is the value of the field
        #                     -> <value> can only be a 
	#			 at this time
        #               <type> is the format in which
	#		      <value> should be packed
	#
	# NOTE: Keeping it as a hash to make it simple
	#

	#
	# get value corresponding to a key
	#
	def get_value(self, key):
		value = None
		for iter1 in self.config_obj_list:
			if iter1.key == key:
				try:
					value = iter1.value
					break					
				except:
					value = None
		return value

	#
	# get type corresponding to a key
	#
	def get_type(self, key):
		tp = None
		for iter1 in self.config_obj_list:
			if iter1.key == key:
				try:
					tp = iter1.tp
					break					
				except:
					tp = None
		return tp
	#
	# set value for a key
	#
	def set_value(self, key, value):
		for iter1 in self.config_obj_list:
			if iter1.key == key:
				iter1.value = value
				break

	#
	# set type for a key
	#
	def set_type(self, key, tp):
		for iter1 in self.config_obj_list:
			if iter1.key == key:
				iter1.tp = tp
				break
		

	#
	# get length of value of a key
	#
	def get_len(self, key):
		ln = None
		for iter1 in self.config_obj_list:
			if iter1.key == key:
				ln = len(iter1.value)
				break
		return ln

	#
	# Get random string of mentioned size
	#
	def get_random_string(self, num_bytes):
		word = ''
		for i in range(num_bytes):
        		word += random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
		return word

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
	def CreateClientHello(self):
		if self.comm.config.get_value(
			"client_hello_hs_cipher_suites") == "DECIDE":
	                if self.cipher != None:
        	                self.set_value(
					"client_hello_hs_cipher_suites",
                	                self.cipher)
				self.set_type(
					"client_hello_hs_cipher_suites",
					">H")

	                        self.set_value(
					"client_hello_hs_cipher_suites_len", 
					2)
				self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")
			else:
				self.set_value(
					"client_hello_hs_cipher_suites", 
					self.cipher)
				self.set_type(
					"client_hello_hs_cipher_suites", 
					">H")

	                        self.set_value(
					"client_hello_hs_cipher_suites_len", 
					2)
				self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")

			if self.comm.config.get_value(
				"client_hello_hs_cipher_suites_len") == "DECIDE":
				if self.cipher != None:
	                                self.set_value(
					"client_hello_hs_cipher_suites_len", 
					2)
					self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")
				else:
					self.set_value(
						"client_hello_hs_cipher_suites_len",
						len(self.cipher))
					self.set_type(
						"client_hello_hs_cipher_suites_len", 
						">H")

		else:
			if self.comm.config.get_value(
				"client_hello_hs_cipher_suites_len") == "DECIDE":
				setting = "%d:>H" % (
				len(self.get_value("client_hello_hs_cipher_suites")))
				self.set_value(
					"client_hello_hs_cipher_suites_len", 
				len(self.get_value(
					"client_hello_hs_cipher_suites")))
				self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")

		#
		# Handle client random
		#
		if self.comm.config.get_value(
			"client_hello_hs_client_random") == "DECIDE":
			self.set_value(
				"client_hello_hs_client_random", 
				DEFAULT_CH_CLIENT_RANDOM)
			self.set_type(
				"client_hello_hs_client_random", "S")

		self.sslStruct['cHelloRB'] = \
			self.get_value("client_hello_hs_client_random")

		#
		# Handle compression methods
		#
		if self.comm.config.get_value(
			"client_hello_hs_compression_methods") == "DECIDE":
			setting = pack('H', 1)
			self.set_value(
				"client_hello_hs_compression_methods", 
				setting)
			self.set_type(
				"client_hello_hs_compression_methods", "H")
		
		#
		# Length of handshake part = 
		# 	Length of handshake ssl version (H) +
		#	Length of client random (32 bytes) +
		#	Length of client sid (B) +
		#	Length of cipher_suites_length (H) +
		#	Length of cipher_suites (variable) + 
		#	Length of compression_methods (variable)
		#
		if self.comm.config.get_value(
			"client_hello_hs_length") == "DECIDE":
			self.client_hello_hs_length = calcsize('>HBH') + 32 + \
				int(self.get_value(
					"client_hello_hs_cipher_suites_len")) + \
				2
			self.set_value("client_hello_hs_length",
				self.client_hello_hs_length)
			self.set_type("client_hello_hs_length", ">H")
		else:
			self.client_hello_hs_length = \
				self.get_value("client_hello_hs_length")

		self.set_value("client_hello_hs_length",
			self.client_hello_hs_length)
		self.set_type("client_hello_hs_length", ">H")

		if self.comm.config.get_value(
			"client_hello_record_length") == "DECIDE":
			self.client_hello_record_length = \
				self.client_hello_hs_length + \
				4
		else:
			self.client_hello_record_length = \
				self.get_value("client_hello_record_length")

		self.set_value("client_hello_record_length", 
			self.client_hello_record_length)
		self.set_type("client_hello_record_length", ">H")

		if self.sslRecord == None:
			self.sslRecord = ""
		if self.sslHandshake == None:
			self.sslHandshake = ""
		self.sslStruct['cHelloRB'] = \
			self.get_value("client_hello_hs_client_random")

		for iter1 in self.config_obj_list:
                	if "client_hello_hs" in iter1.key:
	                        value = iter1.value
        	                tp = iter1.tp

        	                #
        	                # packed_value = pack(value) in the form of int
        	                #                       or if that fails, value
        	                #
	                        try:
					if "client_hello_hs_length" in iter1.key:
						packed_value = \
		pack('>B', 0) + pack('>H', self.client_hello_hs_length)
					else:        
						packed_value = \
		pack('%s' % (tp), int(value))
        	                except ValueError:
        	                        packed_value = value

        	                #
        	                # Add packed value
        	                #       
        	                self.sslHandshake = self.sslHandshake + \
					str(packed_value)

		self.sslStruct['cHello'] = self.sslHandshake

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
	def ReadServerHello(self):
		header = self.socket.recv(5)

		if len(header) == 0:
			self.opn = 1
			return 		
		shLen = HexStr2IntVal(header, 3, 4)

		if shLen == 2:
			self.opn = 1

		sHello = ""
		#
		# Added 
		#		
		if shLen > 500:
			header = self.socket.recv(4)
			shLen = HexStr2IntVal(header, 1, 3)
			sHello = header
		#

		self.sslStruct['shLen'] = shLen
		sHello = sHello + self.socket.recv(shLen)

		self.sslStruct['sHello'] = sHello
		self.sslStruct['sHelloRB'] = sHello[6:32+6]


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
	def ReadServerCertificate(self):
		header = self.socket.recv(1)
		packet_type = ord(header[0])
		packet_type_h = header[0]
		if packet_type == 22:
			header = self.socket.recv(4)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = HexStr2IntVal(header, 2, 3)
			self.sslStruct['scLen'] = scLen
			sCertificate = self.socket.recv(scLen)
		else:
			header = self.socket.recv(3)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = HexStr2IntVal(header, 1, 2)
			self.sslStruct['scLen'] = scLen

			packet_extra = packet_type_h + header
			sCertificate = self.socket.recv(scLen)
			sCertificate = packet_extra + sCertificate
			
		self.sslStruct['sCertificate'] = sCertificate[10:]
		self.sslStruct['sCertificateCF'] = sCertificate

		fobject = open(serverCert, 'w')
		fobject.write("-----BEGIN CERTIFICATE-----\n")
		output = base64.b64encode(self.sslStruct['sCertificate'])
		fobject.write(output)
		fobject.write("\n-----END CERTIFICATE-----\n")
		fobject.close()

		sCert = open(serverCert).read()
		self.x509 = X509()
		cert = self.x509.parse(sCert)

		self.x509cc = X509CertChain([self.x509])

###############################################################################
#
# read_server_key_exchange --
#
# 			Function to read a Server Key Exchange Message 
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
	def ReadServerKeyExchange(self):
		header = self.socket.recv(5)
		if len(header) == 0:
			self.opn = 1
			return 0
		scLen = HexStr2IntVal(header, 3, 4)
		self.sslStruct['skeLen'] = scLen
		ske = self.socket.recv(scLen)
		self.sslStruct['ske'] = ske


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
	def ReadServerHelloDone(self):
		header = self.socket.recv(1)
		packet_type = ord(header[0])
		packet_type_h = header[0]

		if packet_type == 22:
			header = self.socket.recv(4)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = HexStr2IntVal(header, 2, 3)
		else:
			header = self.socket.recv(3)
			if len(header) == 0:
				self.opn = 1
				return
			scLen = HexStr2IntVal(header, 1, 2)
	
		if scLen > 0:
			sHelloDone = self.socket.recv(scLen)
			self.sslStruct['sHelloDone'] = sHelloDone
		else:
			self.sslStruct['sHelloDone'] = packet_type_h + \
				header


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

	def SendCTPacket(self):
		recMsg = 	sslRecHeaderDeafult  + \
				Pack2Bytes(len(self.sslHandshake))

		self.sslRecord = recMsg + self.sslHandshake
		
		try:
			self.socket.send(self.sslRecord)
		except:
			self.opn = 1


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
	def SendSSLPacket(self, hsMsg, seq, renegotiate):
			rec = hsMsg
			recLen = len(hsMsg)

			seqNum = seq
			seqNumUnsignedLongLong = pack('>Q', seqNum)
			iHash = pack('b', 22)
			iHash1 = Pack2Bytes(recLen)

			m = sha1()
			m.update(self.sslStruct['wMacPtr'])
			m.update(pad1SHA)
			m.update(seqNumUnsignedLongLong + iHash + iHash1)
			m.update(rec)
			mInt = m.digest()
	
			m1 = sha1()
			m1.update(self.sslStruct['wMacPtr'])
			m1.update(pad2SHA)
			m1.update(mInt)
			mFin = m1.digest()
	
			self.sslStruct['recordPlusMAC'] = rec + mFin

			pad_len = 16 - len(rec + mFin) & 15

			pminus = pad_len - 1
			padding = ''
			for iter in range(0, pad_len):
				padding = padding + struct.pack('B', pminus)
			
			self.sslStruct['recordPlusMAC'] = rec + \
				mFin +  padding
	
			if renegotiate == 1:
				enc_hs_with_reneg = AES.new( 
				self.sslStruct['wKeyPtr'], 
				AES.MODE_CBC, 
				self.sslStruct['wIVPtr'] )
				encryptedData = enc_hs_with_reneg.encrypt(
					self.sslStruct['recordPlusMAC'])

			if renegotiate == 0:
				enc_hs_no_reneg = AES.new( 
				self.sslStruct['wKeyPtr'], 
				AES.MODE_CBC, 
				self.sslStruct['wIVPtr'] )
				encryptedData = enc_hs_no_reneg.encrypt(
					self.sslStruct['recordPlusMAC'])


			packLen = len(encryptedData)

			self.sslStruct['encryptedRecordPlusMAC'] = \
					sslRecHeaderDeafult + \
					Pack2Bytes(packLen) + encryptedData

			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])
			self.sslStruct['wIVPtr'] = encryptedData[\
				len(encryptedData) - 16 :len(encryptedData)]


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
	def SendRecordPacket(self, recMsg, seq):
			rec = recMsg
			recLen = len(recMsg)

			seqNum = seq
			seqNumUnsignedLongLong = pack('>Q', seqNum)
			iHash = pack('b', 23)
			iHash1 = Pack2Bytes(recLen)

			m = sha1()
			m.update(self.sslStruct['wMacPtr'])
			m.update(pad1SHA)
			m.update(seqNumUnsignedLongLong + iHash + iHash1)
			m.update(rec)
			mInt = m.digest()
	
			m1 = sha1()
			m1.update(self.sslStruct['wMacPtr'])
			m1.update(pad2SHA)
			m1.update(mInt)
			mFin = m1.digest()

			self.sslStruct['recordPlusMAC'] = rec + mFin

			pad_len = 16 - len(rec + mFin) & 15
			pminus = pad_len - 1
			padding = ''
			for iter in range(0, pad_len):
				padding = padding + struct.pack('B', pminus)

			self.sslStruct['recordPlusMAC'] = \
				rec + mFin +  padding

			enc_rec = AES.new( self.sslStruct['wKeyPtr'], 
				AES.MODE_CBC, self.sslStruct['wIVPtr'] )
			encryptedData = enc_rec.encrypt(
				self.sslStruct['recordPlusMAC'])
	
			packLen = len(encryptedData)
			self.sslStruct['encryptedRecordPlusMAC'] = \
					sslAppHeaderDefault + \
					Pack2Bytes(packLen) + encryptedData

			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])

			self.sslStruct['wIVPtr'] = \
		encryptedData[len(encryptedData) - 16 :len(encryptedData)]

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
	def ReadCTPacket(self):
			socket = self.socket
			header = self.socket.recv(5)
			recLen = HexStr2IntVal(header, 3, 4)
			data = self.socket.recv(recLen)

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
	def ReadSSLPacket(self):
			header = self.socket.recv(5)
			recLen = HexStr2IntVal(header, 3, 4)

			try:
				data = self.socket.recv(recLen)
			except:
				self.opn = 1
				return

			dec_rec = AES.new( self.sslStruct['rKeyPtr'], 
				AES.MODE_CBC, self.sslStruct['rIVPtr'] )
			decryptedCF = dec_rec.decrypt(data)

			self.sslStruct['rIVPtr'] = data[recLen - 16: recLen]
			self.decryptedData = decryptedCF


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
	def ReadSF(self):
			socket = self.socket
			header = self.socket.recv(5)
			CFLen = HexStr2IntVal(header, 3, 4)
			if CFLen == 1:
				cssSer = self.socket.recv(1)
			header = self.socket.recv(5)
			CFLen = HexStr2IntVal(header, 3, 4)
			CFMessage = self.socket.recv(CFLen)

			dec_hs = AES.new( self.sslStruct['rKeyPtr'], 
				AES.MODE_CBC, self.sslStruct['rIVPtr'] )
			decryptedCF = dec_hs.decrypt(CFMessage)

			self.sslStruct['rIVPtr'] = CFMessage[48:64]

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
	def CreateClientKeyExchange(self):
		sCert = open(serverCert).read()
		self.x509 = X509()
		self.cert = self.x509.parse(sCert)

		self.x509cc = X509CertChain([self.x509])
		ckeArray = array ( 'B', ckePMKey)
		encData = self.cert.publicKey.encrypt(ckeArray)
		encDataStr = encData.tostring()
		self.sslStruct['encryptedPMKey'] = encDataStr
		self.sslStruct['encryptedPMKey_len'] = len(
			self.sslStruct['encryptedPMKey'])


		self.sslStruct['ckeMessage'] = 	ckeMsgHdr + \
			Pack3Bytes(self.sslStruct['encryptedPMKey_len']) + \
			self.sslStruct['encryptedPMKey']

		self.encrypted = 0
		self.sslHandshake = self.sslStruct['ckeMessage']	

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

	def CreateMasterSecret(self):
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
	def CreateFinishedHash(self):
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
		self.md5Hash = m2.digest()

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

		self.shaHash = s2.digest()


		self.sslStruct['cFinished'] = "\x14\x00\x00\x24" + \
					self.md5Hash + self.shaHash

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

	def CreateKeyBlock(self):
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


		if self.cipher == "\x00\x2F":
			self.sslStruct['macSize'] = 20
			self.sslStruct['keyBits'] = 128
			self.sslStruct['keySize'] = \
				self.sslStruct['keyBits'] / 8
			self.sslStruct['ivSize'] = 16
		elif self.cipher == "\x00\x35":
			self.sslStruct['macSize'] = 20
			self.sslStruct['keyBits'] = 256
			self.sslStruct['keySize'] = \
				self.sslStruct['keyBits'] / 8
			self.sslStruct['ivSize'] = 16
			
		macSize = self.sslStruct['macSize']
		keySize = self.sslStruct['keySize']
		ivSize = self.sslStruct['ivSize']


		print "%d:%d" % (0, macSize)
		print "%d:%d" % (macSize, macSize * 2)
		print "%d:%d" % (2 * macSize, 2 * macSize + keySize)
		print "%d:%d" % (2 * macSize + keySize, 2 * macSize + 2 * keySize)
		print "%d:%d" % (2 * macSize + 2 * keySize, 2 * macSize + \
				2 * keySize + ivSize)
		print "%d:%d" % (2 * macSize + \
				2 * keySize + ivSize, 2 * macSize + \
				2 * keySize + 2 * ivSize)

		self.sslStruct['wMacPtr'] = self.sslStruct['keyBlock']\
			[0:macSize]
		self.sslStruct['rMacPtr'] = self.sslStruct['keyBlock']\
			[macSize:macSize * 2]
		self.sslStruct['wKeyPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize: 2 * macSize + keySize]
		self.sslStruct['rKeyPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize + keySize: 2 * macSize + 2 * keySize]
		self.sslStruct['wIVPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize + 2 * keySize: 2 * macSize + \
				2 * keySize + ivSize]
		self.sslStruct['rIVPtr'] = self.sslStruct['keyBlock']\
			[2 * macSize + \
				2 * keySize + ivSize: 2 * macSize + \
				2 * keySize + 2 * ivSize]

	def pBanner(self, string):
		if self.debugFlag == 1:
			sys.stdout.write("\n### INFO: %s ###\n" % (string))
			
	def HexStrDisplay(self, label, string):
		if self.debugFlag == 1:
			sys.stdout.write("\n%s:\n" % (label))
			strList = string.rsplit('0x')
			chNum = 1
			for item in strList[1:]:
				sys.stdout.write(rjust(item, 3, '0'))
				if (chNum == 8):
					sys.stdout.write('-')
				if (chNum == 16):
					sys.stdout.write('\n')
					chNum = 0
				chNum += 1

	def log(self, data):
		if self.debugFlag == 1:
			self.comm.logger.toboth(data)
		else:
			self.comm.logger.tofile(data)
