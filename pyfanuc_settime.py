	def settime(self,h=None,m=0,s=0): #new version
		"""
		Set Time to Parameter-Values or actual PC-Time
		variant 1 - requests nothing for actual PC-Time to set
		variant 2 - requests hour,optional minute (default 0),optional second (default 0)
		"""
		if h is None:
			t=time.localtime()
			h,m,s=t.tm_hour,t.tm_min,t.tm_sec

		return self._req_rdsingle(1,1,0x46,1,0,0,0,12,pack(">xxxxxxHHH",h,m,s))['error']

	def settime_old(self,h=None,m=0,s=0): #OLD
		"""
		Set Time to Parameter-Values or actual PC-Time
		variant 1 - requests nothing for actual PC-Time to set
		variant 2 - requests hour,optional minute (default 0),optional second (default 0)
		"""
		if h is None:
			t=time.localtime()
			h,m,s=t.tm_hour,t.tm_min,t.tm_sec
		self.sock.sendall(self._encap(pyfanuc.FTYPE_VAR_REQU,self._req_rdsub(1,1,0x46,1,0,0,0,12)+b'\x00'*6+pack(">HHH",h,m,s)))
		t=self._decap(self.sock.recv(1500))
		if t["len"]==18:
			if t["ftype"]==pyfanuc.FTYPE_VAR_RESP and unpack(">HHH",t["data"][0][0:6])==(1,1,0x46):
				return unpack(">h",t["data"][0][6:8])[0]
