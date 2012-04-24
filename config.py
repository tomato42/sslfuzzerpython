from collections import OrderedDict
import re
from constants import *
class config:

	def __init__(self, config_file):
		self.config_file = config_file
		self.config_fd = None
		self.config_hash =  OrderedDict()
		self.read_error = 0
		self.config_status = CONFIG_VALID
		self.config_content = None
		self.valid_lines = 0
	
        #
        # Parse and validate the config file
        #
	def parse_and_validate(self):
		try:
			self.config_fd = open(self.config_file, 'r')
		except:
			self.read_error = 1

		if self.config_fd != None:
			self.config_content = self.config_fd.readlines()

		        for line in self.config_content:
				line = line.strip()
				if re.match("^#.*$", line):
					continue
				if re.match("^$", line):
					continue
				if line:

					key = line.split("->")[0].strip()
					value = line.split("->")[1].strip()
					reg_match = re.match("^.*(\s*->\s*){1}\
(\s*((RANDOM|DECIDE|INFINITE)\s*)|(.*)){1}(\s*:\s*(([>]*[HIBSR])|(NA))\s*){1}$", 
line)
					if reg_match:
						self.config_hash[key] = value
						self.config_status = CONFIG_VALID
						self.valid_lines += 1
					else:
						
						self.config_status = CONFIG_INVALID
						break
			
					
		
	def get_value(self, key):
		value = None
		try:
			value = self.config_hash[key].rsplit(":", 1)[0].strip()
		except:
			value = None
		return value

	def get_type(self, key):
		tp = None
		tp = self.config_hash[key].rsplit(":", 1)[1].strip()
		return tp

	def get_keys(self):
		return self.config_hash.keys()

	def get_values(self):
		return self.config_hash.values()

	def close(self):
		if self.config_fd != None:
			self.config_fd.close()
