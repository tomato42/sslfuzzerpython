import sys
from struct import *
from string import *
import constants
from constants import *

###############################################################################
#
# Str2HexStr --
#
# 			Function to convert a string to a hexadecimal string
#
# Results:
#			1. Takes a string
#			2. Converts ascii value of each character to hex
#			3. Creates a string of hex values by concatenating
#			4. Returns concatenated value
#
# Example:
#			Str2HexStr('ab') = '0x61 0x62 '
#			
# Side Effects:
#			None
###############################################################################
def Str2HexStr(s):
		hexStr = ''
		for char in s:
			asciiValue = hex(ord(char))
			hexStr = str(hexStr) + asciiValue + ' '
		return hexStr

###############################################################################
#
# RevString --
#
# 			Reverses a string
#
# Results:
#			1. Takes a string as input
#			2. Returns the reversed string
#
# Example:
#			RevString('suchi' = 'ihcus'
#			
# Side Effects:
#			None
###############################################################################
def RevString(string):
		srlist = list(string)
		srlist.reverse()
		return ''.join(srlist)

###############################################################################
#
# HexStr2IntVal --
#
# 			Function to convert 2 bytes of a hexadecimal string to 
#			Integer value
#
# Results:
#			1. Takes a string, starting position and ending position as input
#			2. Converts the two bytes at starting position and ending position 
#				to Integar
#			3. Returns the integer
# 				Note: Maximum value of converted Integer is 32767 (0x7fff)
#
# Example:
#			HexStr2IntVal('\x00\xcd', 0, 1) = 205
#			HexStr2IntVal('\x7f\xff', 0, 1) = 32767
#			HexStr2IntVal('\xaa\xbb\x7f\xff', 2, 3) = 32767
#			
# Side Effects:
#			None
###############################################################################
def HexStr2IntVal(string, startPos, endPos):
		content = string[endPos]+string[startPos]
		return unpack('H', content)[0]


###############################################################################
#
# Pack3Bytes --
#
#			Function to create a 3 byte hex string containing integer value
#
# Results:
#			1. Takes a integer as input
#			2. Creates a 3 byte hex string representing integer and returns it
#
# Side Effects:
#			None
###############################################################################
def Pack3Bytes(integer):
	if (integer <= 0xffff):
		content = '\x00' + RevString(pack('h', integer))
	else:
		topByte = hex(integer >> 16 & 0xff)
		integer = integer & 0xffff
		content = str(topByte) + RevString(pack('h', integer))

	return content

###############################################################################
#
# Pack2Bytes --
#
#			Function to create a 2 byte hex string containing integer value
#
# Results:
#			1. Takes a integer as input
#			2. Creates a 2 byte hex string representing integer and returns it
#
# Side Effects:
#			None
###############################################################################
def Pack2Bytes(integer):

	if (integer <= 0xff):
		content = RevString(pack('h', integer))
	else:
		content = RevString(pack('h', integer))

	return content


