import socket, sys, random, time, getopt, copy, os, re
from struct import *
from collections import OrderedDict
from logger import *
from config import *
from constants import *
#
# The following function will popluate the config hash
# with values wherever there are RANDOM numbers required
#
def populate_random_numbers(comm, libSSL):
	for key in comm.config.get_keys():
		value = comm.config.get_value(key)
		tp_orig = comm.config.get_type(key)
		if (tp_orig[0] == "<") or (tp_orig[0] == ">"):
			tp = tp_orig[1:]
		else:
			tp = tp_orig
		if (value == "RANDOM"):
			if (tp_orig == "I") or (tp == "H") or (tp == "B"):
				rand_limit = eval(tp + '_LIMIT')
				r = random.randrange(0, rand_limit)
				setting = "%s:%s" % (r, tp_orig)
				libSSL.set_value(key, setting)
			elif tp == "S":
				rand_limit = eval(tp + '_LIMIT')
				r = libSSL.get_random_string(S_LIMIT)
				setting = "%s:%s" % (r, tp_orig)
				libSSL.set_value(key, setting)
			elif re.match("^.*I", tp) or re.match("^.*H", tp) \
					or re.match("^.*B", tp):
				rand_limit = int(tp[:-1])
				r = random.randrange(0, rand_limit)
				setting = "%s:%s" % (r, tp_orig)
				libSSL.set_value(key, setting)
			elif re.match("^.*S", tp):
				rand_limit = int(tp[:-1])
				r = libSSL.get_random_string(rand_limit)
				setting = "%s:%s" % (r, tp_orig)
				libSSL.set_value(key, setting)


