class common:
	def __init__(self, logger = None, host = None, port = None, config = None, ssl_config_hash = None, ca = None):
		self.logger = logger
		self.host = host
		self.port = port
		self.config = config
		self.ssl_config_hash = ssl_config_hash
		self.ca = ca

