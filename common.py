class common:
	def __init__(self, logger = None, host = None, port = None, config = None, config_obj_list = None, ca = None, cipher = None):
		self.logger = logger
		self.host = host
		self.port = port
		self.config = config
		self.config_obj_list = config_obj_list
		self.ca = ca
		self.cipher = cipher

