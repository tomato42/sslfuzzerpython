#!/usr/bin/python

import os, sys, socket, string, struct, base64, hashlib, copy, random, hmac, math

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
# LibTLS --
#
# 			TLS Class for Fuzzer
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


class LibTLS:
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
		self.cipher = comm.cipher

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
	# get random string of num_bytes bytes
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
					len(self.cipher))
				self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")
			else:
				self.set_value(
					"client_hello_hs_cipher_suites", 
					DEFAULT_CH_CIPHER_SUITES_VALUE)
				self.set_type(
					"client_hello_hs_cipher_suites", 
					">H")

	                        self.set_value(
					"client_hello_hs_cipher_suites_len", 
					len(DEFAULT_CH_CIPHER_SUITES_VALUE))
				self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")

			if self.comm.config.get_value(
				"client_hello_hs_cipher_suites_len") == "DECIDE":
				if self.cipher != None:
	                                self.set_value(
					"client_hello_hs_cipher_suites_len", 
					len(self.cipher))
					self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")
				else:
					self.set_value(
					"client_hello_hs_cipher_suites_len",
					len(DEFAULT_CH_CIPHER_SUITES))
					self.set_type(
					"client_hello_hs_cipher_suites_len", 
					">H")

		else:
			if self.comm.config.get_value(
				"client_hello_hs_cipher_suites_len") == "DECIDE":
				setting = "%d:>H" % (len(self.get_value(
					"client_hello_hs_cipher_suites")))
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
			self.set_type("client_hello_hs_client_random", 
				"S")

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
				"client_hello_hs_compression_methods", 
				"H")
		
		#
		# Length of handshake part = 
		# 	Length of handshake ssl version (H) +
		#	Length of client random (32 bytes) +
		#	Length of client sid (B) +
		#	Length of cipher_suites_length (H) +
		#	Length of cipher_suites (variable) + 
		#	Length of compression_methods (variable)
		#
		if self.comm.config.get_value("client_hello_hs_length")\
			 == "DECIDE":
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

		if self.comm.config.get_value("client_hello_record_length") \
			== "DECIDE":
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
						  pack('>B', 0) + \
						  pack('>H', 
						  self.client_hello_hs_length)
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

		count = 0
		final_output = ""
		for iter1 in output:
			final_output += iter1
			count += 1
			if count == 64:
				count = 0
				final_output += "\r\n"

		fobject.write(final_output)
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
		recMsg = 	tls12RecHeaderDefault  + \
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
			recLen = len(rec)
			rec_len_packed = pack('>H', recLen)

			self.seqNum = pack('>Q', seq)

			m = hmac.new(self.sslStruct['wMacPtr'], 
				digestmod=sha1)
			m.update(self.seqNum)
			m.update("\x16")
			m.update("\x03")
			m.update("\x03")
			m.update(rec_len_packed)
			m.update(rec)
			m = m.digest()

			#
			# As per 6.2.3.2 (2)(a) in the link below:
			#  http://rfc-ref.org/RFC-TEXTS/4346/chapter6.html
			#
			# Data to be encrypted = R ^ mask + Plain text
			#
			# Mask is set to 0, hence 
			#
			# Data to be encrypted = R + Plain text
			# 
			# where, 
			#  R = A random string of length == block length
			#
			# IV used for encryption is the calculated IV during
			# 	key block creation
			#
			self.HexStrDisplay("Final MAC", Str2HexStr(m))
	
			currentLength = len(rec + m) + 1
			blockLength = 16
			pad_len = blockLength - \
				(currentLength % blockLength)

			if pad_len == blockLength:
				pad_len = 0

			self.log("Padding Length: %s" % (str(pad_len)))

			padding = ''
			for iter in range(0, pad_len + 1):
				padding = padding + \
				struct.pack('B', pad_len)

			self.HexStrDisplay("Padding", Str2HexStr(padding))
			
			self.sslStruct['recordPlusMAC'] = \
				R + rec + m + padding
			self.HexStrDisplay("Final Packet", Str2HexStr(
				self.sslStruct['recordPlusMAC']))
	
			if renegotiate == 1:
				enc_hs_with_reneg = \
AES.new( self.sslStruct['wKeyPtr'], AES.MODE_CBC, self.sslStruct['wIVPtr'])
				encryptedData = \
enc_hs_with_reneg.encrypt(self.sslStruct['recordPlusMAC'])

			if renegotiate == 0:
				enc_hs_wo_reneg = \
AES.new( self.sslStruct['wKeyPtr'], AES.MODE_CBC, self.sslStruct['wIVPtr'] )
				encryptedData = \
enc_hs_wo_reneg.encrypt(self.sslStruct['recordPlusMAC'])


			packLen = len(encryptedData)

			self.sslStruct['encryptedRecordPlusMAC'] = \
				tls12RecHeaderDefault + \
				Pack2Bytes(packLen) + encryptedData
			self.HexStrDisplay("Encrypted Packet",
				Str2HexStr(self.sslStruct['encryptedRecordPlusMAC']))
			
			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])



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
			recLen = len(rec)
			rec_len_packed = pack('>H', recLen)

			self.seqNum = pack('>Q', seq)

			self.HexStrDisplay("seq Num", Str2HexStr(self.seqNum))

			m = hmac.new(self.sslStruct['wMacPtr'], 
				digestmod=sha1)
			m.update(self.seqNum)
			m.update("\x17")
			m.update("\x03")
			m.update("\x03")
			m.update(rec_len_packed)
			m.update(rec)
			m = m.digest()

			#
			# As per 6.2.3.2 (2)(a) in the link below:
			#  http://rfc-ref.org/RFC-TEXTS/4346/chapter6.html
			#
			# Data to be encrypted = R ^ mask + Plain text
			#
			# Mask is set to 0, hence 
			#
			# Data to be encrypted = R + Plain text
			# 
			# where, 
			#  R = A random string of length == block length
			#
			# IV used for encryption is the calculated IV during
			# 	key block creation
			#
			self.HexStrDisplay("Final MAC", Str2HexStr(m))
	
			currentLength = len(rec + m) + 1
			blockLength = len(self.sslStruct['wIVPtr'])
			pad_len = blockLength - \
				(currentLength % blockLength)

			if pad_len == blockLength:
				pad_len = 0

			self.log("Padding Length: %s" % (str(pad_len)))

			padding = ''
			for iter in range(0, pad_len + 1):
				padding = padding + \
				struct.pack('B', pad_len)

			self.HexStrDisplay("Padding", Str2HexStr(padding))
			
			self.sslStruct['recordPlusMAC'] = \
				R + rec + m + padding
			self.HexStrDisplay("Final Packet", Str2HexStr(
				self.sslStruct['recordPlusMAC']))
	
			enc_rec = AES.new( self.sslStruct['wKeyPtr'], AES.MODE_CBC, self.sslStruct['wIVPtr'])
			encryptedData = \
enc_rec.encrypt(self.sslStruct['recordPlusMAC'])

			packLen = len(encryptedData)

			self.sslStruct['encryptedRecordPlusMAC'] = \
				tls12AppHeaderDefault + \
				Pack2Bytes(packLen) + encryptedData
			self.HexStrDisplay("Encrypted Packet",
				Str2HexStr(self.sslStruct['encryptedRecordPlusMAC']))
			
			self.socket.send(
				self.sslStruct['encryptedRecordPlusMAC'])

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
			self.log(str(data))

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
			decrypted_data = dec_rec.decrypt(data)

			self.decryptedData = decrypted_data

			self.HexStrDisplay("DecryptedData", 
				Str2HexStr(self.decryptedData))

##############################################################################
#
# ReadSF --
#
# 			Function to read ServerFinished Message from server
#
# Results:
#			1. Reads ChangeCipherSpec and ServerFinished Message 
#				from server
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

###############################################################################
#
# P_hash --
#
# 			Function to create a P_Hash 
#
# Results:
#			1. Creates a hash based on secret, seed and 
#				returns as many bytes as requested
#				in the length parameter
#
# Side Effects:
#			None
###############################################################################
	def P_hash(self, hashModule, secret, seed, length):
	    	bytes = bytearray(length)
	    	A = seed
	    	index = 0
	    	while 1:
			A = hmac.HMAC(secret, A, hashModule).digest()
			output = hmac.HMAC(secret, A+seed, hashModule).digest()
			for c in output:
		    		if index >= length:
		        		return bytes
		    		bytes[index] = c
		    		index += 1
	    
###############################################################################
#
# PRF --
#
# 			Pseudo Random Function 
#
# Results:
#			1. TLS PRF is performed by this function
#
# Side Effects:
#			None
###############################################################################
	def PRF(self, secret, label, seed, length):
		seed = label + seed

		p_sha256 = self.P_hash(sha256, secret, seed, length)

	    	return p_sha256


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
		#
		# TLS encryption
		#
		sCert = open(serverCert).read()
		x509 = X509()
		cert = x509.parse(sCert)

		x509cc = X509CertChain([x509])
		ckeArray = array ( 'B', tls12CKEPMKey)
		encData = cert.publicKey.encrypt(ckeArray)
		encDataStr_tls = encData.tostring()

		self.sslStruct['encryptedPMKey'] = encDataStr_tls
		self.sslStruct['encryptedPMKey_len'] = \
			len(self.sslStruct['encryptedPMKey'])

		self.sslStruct['ckeMessage'] = 	ckeMsgHdr + \
			Pack3Bytes(
			self.sslStruct['encryptedPMKey_len'] + 2) + \
			Pack2Bytes(
			self.sslStruct['encryptedPMKey_len']) + \
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
# master_secret = PRF(pre-master secret, "master secret", client random, 
#	server random, 48)
#
	def CreateMasterSecret(self):
		self.sslStruct['masterSecret'] = self.PRF(tls12CKEPMKey,
					"master secret", 
					self.sslStruct['cHelloRB'] + \
					self.sslStruct['sHelloRB'],
					48)

		master_secret_str = ""
		for ch in self.sslStruct['masterSecret']:
			master_secret_str += chr(ch)

		self.sslStruct['masterSecret'] = master_secret_str


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
#   ClientFinishedMessage = md5Hash + sha1Hash
#
#			    md5Hash = MD5(handshake_messages)
#			
#			    shaHash = SHA(handshake_messages)
#
	def CreateFinishedHash(self):
		s1 = sha256()
		s1.update(self.sslStruct['cHello'])
		s1.update(self.sslStruct['sHello'])
		s1.update(self.sslStruct['sCertificateCF'])
		s1.update(self.sslStruct['sHelloDone'])
		s1.update(self.sslStruct['ckeMessage'])
		self.shaHash = s1.digest()
		

		cFinished = self.PRF(self.sslStruct['masterSecret'], 
			'client finished',
			self.shaHash, 12)

		cFinished_str = str(cFinished)
		cfLen = len(cFinished_str)
		cfLen = Pack3Bytes(cfLen)

		self.sslStruct['cFinished'] = "\x14" + cfLen + \
					cFinished_str



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
#	  PRF(master_secret + 'key expansion', client random + server random)
#

	def CreateKeyBlock(self):
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
			
		self.sslStruct['reqKeyLen'] = 2 * self.sslStruct['macSize'] + \
					2 * self.sslStruct['keySize'] + \
					2 * self.sslStruct['ivSize']

		self.sslStruct['keyBlock'] = ""


		seed = self.sslStruct['sHelloRB'] + self.sslStruct['cHelloRB']
		self.sslStruct['keyBlock'] = \
		self.PRF(self.sslStruct['masterSecret'], 
			'key expansion', seed, self.sslStruct['reqKeyLen'])


		keyBlock_str = ""
		for ch in self.sslStruct['keyBlock']:
			keyBlock_str += chr(ch)

		self.sslStruct['keyBlock'] = keyBlock_str

		macSize = self.sslStruct['macSize']
		keySize = self.sslStruct['keySize']
		ivSize = self.sslStruct['ivSize']

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
