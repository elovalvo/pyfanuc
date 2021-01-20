#!/usr/bin/env python3
import socket,time,datetime
from struct import pack,unpack

class pyfanuc(object):
	def __init__(self, ip, port=8193):
		self.sock=None
		self.ip=ip
		self.port=port
		self.connected=False
	FTYPE_OPN_REQU=0x0101;FTYPE_OPN_RESP=0x0102
	FTYPE_VAR_REQU=0x2101;FTYPE_VAR_RESP=0x2102;FTYPE_VAR_ERR=0x2103
	FTYPE_CLS_REQU=0x0201;FTYPE_CLS_RESP=0x0202
	FRAME_SRC=b'\x00\x01'
	FRAME_DST=b'\x00\x02';FRAME_DST2=b'\x00\x01'
	FRAMEHEAD=b'\xa0\xa0\xa0\xa0'
	def connect(self):
		"Establish connection to machine and set parameters with sysinfo"
#		try:
		self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.settimeout(5)
		self.sock.connect((self.ip,self.port))
		self.sock.settimeout(1)
		self.sock.sendall(self._encap(pyfanuc.FTYPE_OPN_REQU,pyfanuc.FRAME_DST))
		data=self._decap(self.sock.recv(1500))
		if data["ftype"]==pyfanuc.FTYPE_OPN_RESP:
			self.connected=True
		self.getsysinfo()
#		except:
#		print("ERROR")
#		self.sock=None
#		self.connected=False
		return self.connected
	def disconnect(self):
		"Disconnect the connection to the machine"
		if self.connected:
			self.sock.sendall(self._encap(pyfanuc.FTYPE_CLS_REQU,b''))
			data=self._decap(self.sock.recv(1500))
			if data["ftype"]==pyfanuc.FTYPE_CLS_RESP:
				return True
		return False

	def _encap(self,ftype,payload,fvers=1):
		"intern function - Encapsulate packetdata"
		if ftype==pyfanuc.FTYPE_VAR_REQU:
			pre=[]
			if isinstance(payload,list):
				for t in payload:
					pre.append(pack(">H",len(t)+2)+t)
				payload=pack(">H",len(pre))+b''.join(pre)
			else:
				payload=pack(">HH",1,len(payload)+2)+payload
		return pyfanuc.FRAMEHEAD+pack(">HHH",fvers,ftype,len(payload))+payload
	def _decap(self,data):
		"intern function - Decapsulate packetdata"
		if len(data)<10:
			return {"len":-1}
		if not data.startswith(b'\xa0'*4):
			return {"len":-1}
		fvers,ftype,len1=unpack(">HHH",data[4:10])
		if len1+10 != len(data):
			if (len1+10)>len(data):
				return {"len":-1,"missing":len1+10-len(data)}
			else:
				return {"len":-1}
		if len1==0:
			return {"len":0,"ftype":ftype,"fvers":fvers,"data":b'0'}
		data=data[10:]
		if ftype==pyfanuc.FTYPE_VAR_RESP:
			re=[]
			qu=unpack(">H",data[0:2])[0]
			n=2
			for t in range(qu):
				le=unpack(">H",data[n:n+2])[0]
				re.append(data[n+2:n+le])
				n+=le
			return {"len":len1,"ftype":ftype,"fvers":fvers,"data":re}
		else: # ftype==FTYPE_OPN_RESP or ftype==FTYPE_CLS_RESP
			return {"len":len1,"ftype":ftype,"fvers":fvers,"data":data}
	def _req_rdsingle(self,c1,c2,c3,v1=0,v2=0,v3=0,v4=0,v5=0,pl=b""):
		"intern function - pack simple command"
		cmd=pack(">HHH",c1,c2,c3)
		self.sock.sendall(self._encap(pyfanuc.FTYPE_VAR_REQU,cmd+pack(">iiiii",v1,v2,v3,v4,v5)+pl))
		dat=b''
		while True:	#MULTI-Packet
			dat+=self.sock.recv(1500)
			t=self._decap(dat)
			if not "missing" in t:
				break
		if t['len']==0: #ZEROLENGTH
			return {'len':-1,'error':-1,'suberror':0}
		elif t['ftype']!=pyfanuc.FTYPE_VAR_RESP: #NOT RESPONSE
			return {'len':-1,'error':-1,'suberror':1}
		elif t['data'][0].startswith(cmd):
			return {	'cmd':unpack('>HHH',t['data'][0][:6]),
						'len':unpack('>H',t['data'][0][12:14])[0],
						'data':t['data'][0][14:],
						'error':unpack('>h',t['data'][0][6:8])[0],
						'errdetail':unpack('>h',t['data'][0][8:10])[0]	}
		else:
			return {'len':-1,'error':-1,'suberror':2}
	def _req_rdmulti(self,lst):
		"intern function - pack multiple commands - multipacket version"
		self.sock.sendall(self._encap(pyfanuc.FTYPE_VAR_REQU,lst))
		dat=b''
		while True: #MULTI-Packet
			dat+=self.sock.recv(1500)
			t=self._decap(dat)
			if not "missing" in t:
				break
		if t['len']==0: #ZEROLENGTH
			return {'len':-1,'error':-1,'suberror':0}
		elif t['ftype']!=pyfanuc.FTYPE_VAR_RESP: #NOT RESPONSE
			return {'len':-1,'error':-1,'suberror':1}
		if len(lst) != len(t['data']): #WRONG subpacket-count
			return {'len':-1,'error':-1,'suberror':3}
		for x in range(len(t['data'])):
			if t['data'][x][0:6] == lst[x][0:6]:
				v=dict(zip(['error','errdetail','len'],unpack('>hhxxH',t['data'][x][6:14])))
				v['cmd']=unpack('>HHH',t['data'][x][:6]),
				v['data']=t['data'][x][14:]
				t['data'][x]=v
			else:
				return {"len":-1,'error':-1,'suberror':2}
		return t
	def _req_rdsub(self,c1,c2,c3,v1=0,v2=0,v3=0,v4=0,v5=0):
		"intern function - pack subfunction info"
		return pack(">HHHiiiii",c1,c2,c3,v1,v2,v3,v4,v5)
	def _decode8(self,val):
		"intern function - decode value from 8 bytes"
		if val[5]==2 or val[5]==10:
			if val[-2:]==b'\xff'*2:
				return float('Nan')
			else:
				return unpack(">i",val[0:4])[0]/val[5]**val[7]
	def _encode8(self,val,exp=2):
		"intern function - encode value to 8 bytes"
		if isinstance(val,int):
			return pack(">i",val)+b"\0\x02\0\0"
		else:
			return pack(">i",val[0:4])[0]/val[5]**val[7]

	def statinfo(self):
		"""
		Get state of machine
		"""
		st=self._req_rdsingle(1,1,0x19,0)
		if (self.sysinfo["cnctype"]==b"16" or self.sysinfo["cnctype"]==b"31") and st["len"]==0xe:
			return dict(zip(['aut','run','motion','mstb','emegency','alarm','edit'],
			unpack(">HHHHHHH",st["data"])))
	def getdate(self): #v
		"""
		Get date
		returns [YEAR,MONTH,DAY]
		"""
		st=self._req_rdsingle(1,1,0x45,0)
		if st["len"]==0xc:
			return unpack(">HHH",st["data"][0:6])
	def gettime(self): #v
		"""
		Get time
		returns [HOUR,MINUTE,SECOND]
		"""
		st=self._req_rdsingle(1,1,0x45,1)
		if st["len"]!=0xc:
			return
		return unpack(">HHH",st["data"][-6:])
	def getdatetime(self): #v
		"""
		Get date and time
		returns time.struct_time
		"""
		st=self._req_rdmulti([self._req_rdsub(1,1,0x45,0),self._req_rdsub(1,1,0x45,1)])
		if st["len"]<0:
			return
		print(st)
		if len(st["data"]) != 2:
			return
		if st['data'][0]['error']!=0 or st["data"][1]['error']!=0:
			return
		if st['data'][0]['len'] == 0xc and st['data'][0]['len'] == 0xc:
			return datetime.datetime(*unpack(">HHHHHH",st["data"][0]['data'][0:6]+st["data"][1]['data'][-6:])).timetuple()
	def settime(self,h=None,m=0,s=0): #new
		"""
		Set Time to Parameter-Values or actual PC-Time
		variant 1 - requests nothing for actual PC-Time to set
		variant 2 - requests hour,optional minute (default 0),optional second (default 0)
		"""
		if h is None:
			t=time.localtime()
			h,m,s=t.tm_hour,t.tm_min,t.tm_sec

		return self._req_rdsingle(1,1,0x46,1,0,0,0,12,pack(">xxxxxxHHH",h,m,s))['error']

	def getsysinfo(self): #v
		"""
		Get sysinfo
		returns ['addinfo','maxaxis','cnctype','mttype','series','version','axes']
		"""
		st=self._req_rdsingle(1,1,0x18)
		if st["len"]==0x12:
			self.sysinfo=dict(zip(['addinfo','maxaxis','cnctype','mttype','series','version','axes'],
			unpack(">HH2s2s4s4s2s",st["data"])))

	FORMAT_AXIS,FORMAT_TOOLOFF,FORMAT_MACRO,FORMAT_WORKZOFF,FORMAT_CUTFR=0,1,2,3,4;
	def getformat(self,type=0): #v
		"get typespecific numberformat"
		st=self._req_rdsingle(1,1,0x1b,type)
		if st["len"]>=4+2*2:
			n={'type':type,'count':unpack(">i",st["data"][0:4])[0]}
			t=[]
			for x in range(4,st["len"],4):
				t.append(dict(zip(['decinput','decoutput'],unpack(">HH",st["data"][x:x+4]))))
			if len(t)>1:
				n["dec"]=t
			else:
				n.update(t[0])
			return n

	def readaxesnames(self): #v
		st=self._req_rdsingle(1,1,0x89)
		if st["len"]<0:
			return
		ret=[]
		for t in range(0,st["len"],4):
			a=st["data"][t:t+4]
			ret.append(a[0:a.find(b'\0')].decode())
		return ret

	def readspindlenames(self): #v
		st=self._req_rdsingle(1,1,0x8a)
		if st["len"]<0:
			return
		ret=[]
		for t in range(0,st["len"],4):
			a=st["data"][t:t+4]
			ret.append(a[0:a.find(b'\0')].decode())
		return ret

	ABS=1;REL=2;REF=4;SKIP=8;DIST=16;ABSWO=32;RELWO=64
	ALLAXIS=-1
	def readaxes(self,what=1,axis=ALLAXIS): #v
		r=[]
		axvalues=(("ABS",pyfanuc.ABS,4),("REL",pyfanuc.REL,6),("REF",pyfanuc.REF,1),("SKIP",pyfanuc.SKIP,8),("DIST",pyfanuc.DIST,7),
			  ("ABSWO",pyfanuc.ABSWO,0),("REFWO",pyfanuc.RELWO,2))
		for u,v,w in axvalues:
			if what & v:
				r.append(self._req_rdsub(1,1,0x26,w,axis))
		st=self._req_rdmulti(r)
		if st["len"]<0:
			return
		r={}
		for x in st["data"]:
			ret1=[]
			if x['len'] < 0:
				ret1=None
			else:
				print(x['len'])
				for pos in range(0,x['len'],8):
					value=x['data'][pos:pos+8]
					ret1.append(self._decode8(value))
			for u,v,w in axvalues:
				if what & v:
					r[u]=ret1
					what &= ~v
					break
		return r

	def readsetting(self,axis,first,last=0):
		return self.readparam(axis,first,last=None,param=0)
	def readsettinginfo(self,num,count=1):
		return self.readparaminfo(num,count,param=0)

	def readparam(self,axis,first,last=None,param=1): #param=0 for settings
		"""
		Read Parameter(s)
		or Setting(s) - Paramter with setting-attribut
		"""
		if conn.sysinfo['cnctype']==b'31':
			return self.readparam2(axis,first,last,param)
		if last is None:last=first
		if param==1:
			st=self._req_rdsingle(1,1,0x0e,first,last,axis)
		else:
			st=self._req_rdsingle(1,1,0x29,first,last,axis)
		if st["len"]<0:
			return
		r={}
		for pos in range(0,st["len"],self.sysinfo["maxaxis"]*4+8):
			varname,axiscount,valtype=unpack(">IhH",st["data"][pos:pos+8])
			values={"type":valtype,"axis":axiscount,"data":[]}
			for n in range(pos+8,pos+self.sysinfo["maxaxis"]*4+8,4):
				value=st["data"][n:n+4]
				if valtype==0:
					value=[(value[-1] >> n)& 1 for n in range(7,-1,-1)] #bit 1bit
				elif valtype==1:
					value=value[-1] #byte
				elif valtype==2:
					value=unpack(">h",value[-2])[0] #short
				elif valtype==3:
					value=unpack(">i",value)[0] #int
				if axiscount != -1:
					values["data"].append(value)
					break
				else:
					values["data"].append(value)
			r[varname]=values
		return r
	def readparaminfo(self,num,count=1,param=1): #param=0 for settings
		if param==1:
			st=self._req_rdsingle(1,1,0x10,num,count)
		else:
			st=self._req_rdsingle(1,1,0x2B,num,count)
		if st["len"]<0:
			return
		r={"next":unpack(">i",st["data"][4:8])[0],"before":unpack(">i",st["data"][0:4])[0]}
		for pos in range(8,st["len"],8):
			r[unpack(">i",st["data"][pos:pos+4])[0]]={'type':unpack(">i",st["data"][pos+4:pos+8])[0]}
		return r
	def readparaminfo2(self,num,count=1):
		st=self._req_rdsingle(1,1,0xa0,num,count,0,0,0x10000)
		if st["len"]<0:
			return
		r={"next":unpack(">i",st["data"][4:8])[0],"before":unpack(">i",st["data"][0:4])[0]}
		for pos in range(8,st["len"],4*5):
			r[unpack(">i",st["data"][pos:pos+4])[0]]=dict(zip(['size','array','unit','dim','input','display','others'],unpack(">hhhhhhh",st["data"][pos+4:pos+4+2*7])))
		return r

	def readparam2(self,axis,first,last=None,param=1): #param=0 for settings
		"""
		Read Parameter(s)info
		or Setting(s)info - Paramter with setting-attribut
		"""
		if last is None:last=first
		if param==1:
			st=self._req_rdsingle(1,1,0x8d,first,last,axis)
		else:
			st=self._req_rdsingle(1,1,0x90,first,last,axis)
		if st["len"]<0:
			return
		r={}
		for pos in range(0,st["len"],self.sysinfo["maxaxis"]*8+8):
			varname,axiscount,valtype=unpack(">IhH",st["data"][pos:pos+8])
			values={"type":valtype,"axis":axiscount,"data":[]}
			for n in range(pos+8,pos+self.sysinfo["maxaxis"]*8+8,8):
				value=st["data"][n:n+8]
				if valtype==0:
					value=[(value[3] >> n)& 1 for n in range(7,-1,-1)]
				elif valtype==1 or valtype==2 or valtype==3:
					value=unpack(">i",value[0:4])[0]
				elif valtype==4:
					value=self._decode8(value)  #real
				if axiscount != -1:
					values["data"].append(value)
					break
				else:
					values["data"].append(value)
			r[varname]=values
		return r

	def readparameters(self,axis,first,last): #Elegant Version
		paracmd=0x0e if conn.sysinfo['cnctype']!=b'31' else 0x8d
		paralen=4 if conn.sysinfo['cnctype']!=b'31' else 8

		st=self._req_rdmulti([self._req_rdsub(1,1,0x10,first,1),
			self._req_rdsub(1,1,0x10,last,1),
			self._req_rdsub(1,1,paracmd,first,last,axis)])
		if st["len"]<0:
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
						values["data"]=value
						break
					else:
						values["data"].append(value)
				r[varname]=values
				first=varname+1
			if error==2:
				st=self._req_rdsingle(1,1,paracmd,first,last,axis)
				error=st['error']
				if st["len"]<0:
					break
				data=st['data']
				length=st['len']
			else:
				break
		return r

	def readdiag(self,axis,first,last=None):
		if last is None:last=first
		st=self._req_rdsingle(1,1,0x30,first,last,axis)
		if st["len"]<0:
			return
		r={}
		for pos in range(0,st["len"],self.sysinfo["maxaxis"]*4+8):
			varname,axiscount,valtype=unpack(">IhH",st["data"][pos:pos+8])
			values={"type":valtype,"axis":axiscount,"data":[]}
			for n in range(pos+8,pos+self.sysinfo["maxaxis"]*4+8,4):
				value=st["data"][n:n+4]
				if valtype==4 or valtype==0:
					value=value[-1] #bit 1bit / Byte
				elif valtype==1:
					value=unpack(">h",value[-2])[0] #short
				elif valtype==2:
					value=unpack(">i",value)[0] #int
				elif valtype==3:
					value=[(value[-1] >> n)& 1 for n in range(7,-1,-1)] #bit 8bit
				if axiscount != -1:
					values["data"].append(value)
					break
				else:
					values["data"].append(value)
			r[varname]=values
		return r
	def readmacro(self,first,last=None):
		if last is None: last=first
		st=self._req_rdsingle(1,1,0x15,first,last)
		if st["len"]<=0:
			return
		r={}
		for pos in range(0,st["len"],8):
			r[first]=self._decode8(st["data"][pos:pos+8])
			first+=1
		return r
	def readmacro2(self,first,count=1):
		st=self._req_rdsingle(1,1,0xa7,first,count)
		if st["len"]<=0:
			return
		r={}
		for pos in range(0,st["len"],8):
			r[first]=unpack(">d",st["data"][pos:pos+8])[0]
			first+=1
		return r

	def readpmc(self,datatype,section,first,count=1):
		last=first+(1<<datatype)*count-1
		st=self._req_rdsingle(2,1,0x8001,first,last,section,datatype)
		if st["len"]<=0:
			return
		r={}
		for x in range(st["len"]>>datatype):
			pos=(1<<datatype)*x
			if datatype==0:
				value=st["data"][pos]
			elif datatype==1:
				value=unpack(">H",st["data"][pos:pos+2])[0]
			elif datatype==2:
				value=unpack(">I",st["data"][pos:pos+4])[0]
			r[first+(1<<datatype)*x]=value
		return r
	def readexecprog(self,chars=256):
		st=self._req_rdsingle(1,1,0x20,chars)
		if st["len"]<=4:
			return
		return {"block":unpack(">i",st["data"][0:4])[0],"text":st["data"][4:].decode()}
	def readprognum(self):
		"""
		Get the running program and main program numbers
		returns [running,main]
		"""
		st=self._req_rdsingle(1,1,0x1c)
		if st["len"]<8:
			return
		return {"run":unpack(">i",st["data"][0:4])[0],"main":unpack(">i",st["data"][4:])[0]}
	def readprogname(self): #31i
		"""
		Get current mainprogname
		returns name with path
		"""
		st=self._req_rdsingle(1,1,0xb9)
		if st["len"]<=0:
			return
		p=st["data"].split(b'\0', 1)[0]
		return p.decode()
	def listprog(self,start=1):
		ret={}
		while True:
			st=self._req_rdsingle(1,1,0x06,start,0x13,2)
			if st["len"] < -1:
				return None
			elif st["len"]==0:
				return ret
			for t in range(0,st["len"],72):
				number,size,comment=unpack(">II64s",st["data"][t:t+72])
				comment=comment.split(b'\0', 1)[0]
				start=number+1
				ret[number]={"size":size,"comment":comment.decode()}
	def readalarm(self):
		"Read alarm Bitfield"
		st=self._req_rdsingle(1,1,0x1a)
		if st["len"]!=4:
			return
		return unpack(">L",st["data"])[0]
	def readalarmcode(self,type,withtext=0,maxmsgs=None,textlength=32):
		"Read alarm code / msg"
		#readalarmmsg	Returns Alarmcode+Msgtext	1,1,0x23,int32 Type,int32 MaxMsgs,int32 0 w/o or 1/2 with text,int32 MaxTextLength
		#											int32 AlarmCode,int32 AlarmType,int32 Axis,int32 TextLength,text/trash
		if maxmsgs is None:
			maxmsgs=int(self.sysinfo['axes'])
		st=self._req_rdsingle(1,1,0x23,type,maxmsgs,withtext,textlength)
		ret=[]
		if st["len"] < 0 :
			return
		for pos in range(0,st["len"],4*4+textlength):
			entry=dict(zip(['alarmcode','alarmtype','axis'],unpack(">iii",st["data"][pos:pos+4*3])))
			txlen=unpack(">i",st["data"][pos+4*3:pos+4*4])[0]
			if txlen>0 and withtext>0:
				entry["text"]=st["data"][pos+4*4:pos+4*4+textlength]
			ret.append(entry)
		return ret

	def readdrives(self):
		"""
		Get drive-names
		returns names
		"""
		st=self._req_rdsingle(1,1,0xae)
		if st["len"]<0:
			return
		ret=[]
		for t in range(0,st["len"],12):
			a=st["data"][t:t+12]
			ret.append(a[0:a.find(b'\0')].decode())
		return ret
	def readdir_current(self,fgbg=1): #31i
		"""
		Get current directory
		requests 1 (default) for foreground or 2 for background
		returns directoryname
		"""
		st=self._req_rdsingle(1,1,0xb0,fgbg)
		if st["len"]<0:
			return
		p=st["data"].split(b'\0', 1)[0]
		return p.decode()
	def readdir_info(self,dir): #31i
		buffer=bytearray(0x100)
		bdir=dir.encode()
		buffer[0:len(bdir)]=bdir
		st=self._req_rdsingle(1,1,0xb4,0,0,0,0,256,buffer)
		if st["len"]>=8:
			return dict(zip(['dirs','files'],unpack(">ii",st["data"])))
		return None
	def readdir(self,dir,first=0,count=10,type=0,size=1): #30i
		buffer=bytearray(0x100)
		bdir=dir.encode()
		buffer[0:len(bdir)]=bdir
		st=self._req_rdsingle(1,1,0xb3,first,count,type,size,256,buffer)
		x=[]
		if st["len"]>=8:
			for t in range(0,st["len"],128):
				n=dict(zip(['type','datetime','unkn','size','attr','name','comment','proctimestamp'],unpack(">h12s6sII36s52s12s",st["data"][t:t+128])))
				del n['unkn']
				if n['type']==1:
					n['comment']=n['comment'].split(b'\0', 1)[0].decode()
					n['datetime']=datetime.datetime(*unpack(">HHHHHH",n['datetime'])).timetuple()
				else:
					n['comment']=None
					n['size']=None
					n['datetime']=None
				n['name']=n['name'].split(b'\0', 1)[0].decode()
				n['type']='D' if n['type']==0 else 'F'
				x.append(n)
			return(x)
		return None
	def readdir_complete(self,dir): #30i
		t=self.readdir_info(dir)
		n=t['dirs']+t['files']
		ret=[]
		for t in range(0,n,10):
			x=self.readdir(dir,first=t,count=10)
			if not x is None:
				ret.extend(x)
			else:
				break
		return ret
	def getprog(self,name): #TEST Stream
		"""
		Get program-file
		requests filename
		returns filecontent
		"""
		if isinstance(name,int):
			q=("O%04i-O%04i" % (name,name)).encode()
		elif isinstance(name,str):
			name=name.upper()
			if self.sysinfo["cnctype"]==b"31":
				name="N:"+name
			else:
				if not name.startswith("O"):
					name="O"+name
				if name.find("-")==-1:
					name=name+"-"+name
			q=name.encode()
		else:
			return -1
		buffer=bytearray(0x204)
		self.sock2=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock2.connect((self.ip,self.port))
		self.sock2.settimeout(1)
		self.sock2.sendall(self._encap(pyfanuc.FTYPE_OPN_REQU,pyfanuc.FRAME_DST2))
		data=self._decap(self.sock2.recv(1500))
		buffer[0:4]=b'\x00\x00\x00\x01'
		buffer[4:4+len(q)]=q #buffer[4:15]=b'\x4f\x30\x31\x30\x30\x2d\x4f\x30\x31\x30\x30'
		self.sock2.sendall(self._encap(0x1501,buffer))
		data=self._decap(self.sock2.recv(1500))
		#print(data)
		f=b''
		n=b''
		while True:
			n+=self.sock2.recv(1500)
			while len(n)>=10:
				if n[:4]==pyfanuc.FRAMEHEAD:
					fvers,ftype,flen=unpack(">HHH",n[4:10])
					if len(n)<flen:
						break
					n=n[10:]
					if ftype==0x1604: #a0 a0 a0 a0 00 02 16 04 05 00
						f+=n[:flen]
						n=n[flen:]
					elif ftype==0x1701: #a0 a0 a0 a0 00 02 17 01 00 00
						self.sock2.sendall(self._encap(0x1702,b'')) #a0 a0 a0 a0 00 01 17 02 00 00
						return f.decode()
				else:
					return -1
		return -1
	def readactfeed(self):
		"""
		Get actual feedrate
		returns feedrate
		"""
		st=self._req_rdsingle(1,1,0x24)
		return self._decode8(st['data']) if st['len']==8 else None
	def readactspindlespeed(self):
		"""
		Get actual spindlespeed
		returns spindlespeed
		"""
		st=self._req_rdsingle(1,1,0x25)
		return self._decode8(st['data']) if st['len']==8 else None

if __name__ == '__main__':
	conn=pyfanuc('192.168.0.70')
	if conn.connect():
		print("connected")
		#print(conn.getdatetime())
		print(conn.readaxes(conn.ABS | conn.REL))
	if conn.disconnect():
		print("disconnected")

#	conn=pyfanuc('192.168.0.61')
#	if conn.connect():
#		print("connected")
#		print(conn.sysinfo)
#		print(conn.readactfeed())
#	if conn.disconnect():
#		print("disconnected")
