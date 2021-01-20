	def readparameters(self,axis,first,last): #VERSION 16
		paracmd=0x0e if conn.sysinfo['cnctype']!=b'31' else 0x8d
		paralen=4 if conn.sysinfo['cnctype']!=b'31' else 8

		st=self._req_rdmulti([self._req_rdsub(1,1,0x10,first,1),
			self._req_rdsub(1,1,0x10,last,1),
			self._req_rdsub(1,1,paracmd,first,last,axis)])
		if st["len"]<0 or "error" in st:
			return
		f=dict(zip(['before','next','num'],unpack(">iii",st["data"][0]['data'][:12])))
		l=dict(zip(['before','next','num'],unpack(">iii",st["data"][1]['data'][:12])))
		if f['num'] != first:
			first=f['num']
		if l['num'] != last:
			last=l['before']
		error,length,data=st["data"][2]['error'],st["data"][2]['len'],st["data"][2]['data']
		r={}
		while True:
			for pos in range(0,length,self.sysinfo["maxaxis"]*paralen+8):
				varname,axiscount,valtype=unpack(">IhH",data[pos:pos+8])
				values={"type":valtype,"axis":axiscount,"data":[]}
				for n in range(pos+8,pos+self.sysinfo["maxaxis"]*paralen+8,paralen):
					value=data[n:n+paralen]
					if valtype==0:
						value=[(value[3] >> n)& 1 for n in range(7,-1,-1)] #bit 1bit
					elif valtype==4:
						value=self._decode8(value)  #real
					elif valtype==1 or valtype==2 or valtype==3: #byte,shert,long
						value=unpack(">i",value[0:4])[0]
					if axiscount != -1:
						values["data"].append(value)
						break
					else:
						values["data"].append(value)
				r[varname]=values
				first=varname+1
			if error==2:
				st=self._req_rdsingle(1,1,paranum,first,last,axis)
				error=st['error']
				if st["len"]<0:
					break
				data=st['data']
				length=st['len']
			else:
				break
		return r
