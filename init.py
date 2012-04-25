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
	for iter1 in comm.config.config_obj_list:
		key = iter1.key
		value = iter1.value
		tp_orig = iter1.tp
		if tp_orig == "NA":
			continue
		else:
			if len(tp_orig) > 1:
				tp = tp_orig[1]
			else:
				tp = tp_orig

			if (value == "RANDOM"):
				rand_limit = eval(tp + '_LIMIT')

				if (tp == "I") or (tp == "H") or (tp == "B"):
					r = random.randrange(0, rand_limit)
					libSSL.set_value(key, r)
					libSSL.set_type(key, tp_orig)
				elif tp == "S":
					r = libSSL.get_random_string(S_LIMIT)
					libSSL.set_value(key, r)
					libSSL.set_type(key, tp_orig)
