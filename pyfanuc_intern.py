def _req_rdsingle(self,c1,c2,c3,v1=0,v2=0,v3=0,v4=0,v5=0,pl=b""):
  "intern function - pack simple command"
  cmd=pack(">HHH",c1,c2,c3)
  self.sock.sendall(self._encap(pyfanuc.FTYPE_VAR_REQU,cmd+pack(">iiiii",v1,v2,v3,v4,v5)+pl))
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
  elif t['data'][0].startswith(cmd):
    return {'cmd':unpack('>HHH',t['data'][:6]),'len':unpack('>H',t['data'][0][12:14])[0],'data':t['data'][0][14:],'error':unpack('>h',t['data'][0][6:8])[0],'errdetail':unpack('>h',t['data'][0][8:10])[0]}
  else:
    return {'len':-1,'error':-1,'suberror':2}
def _req_rdmulti(self,lst):
  "intern function - pack multiple commands - multipacket version"
  self.sock.sendall(self._encap(pyfanuc.FTYPE_VAR_REQU,lst))
  dat=b''
  while True: #MULTI-Packet
    dat+=self.sock.recv(1500)
    t=self._decap(dat)
    if not "missing" in t: break
  if t['len']==0: #ZEROLENGTH
    return {'len':-1,'error':-1,'suberror':0}
  elif t['ftype']!=pyfanuc.FTYPE_VAR_RESP: #NOT RESPONSE
    return {'len':-1,'error':-1,'suberror':1}
  if len(lst) != len(t['data']): #WRONG subpacket-count
    return {'len':-1,'error':-1,'suberror':3}
  for x in range(len(t['data'])):
    if t['data'][x][0:6] == lst[x][0:6]:
      t['data'][x]={'cmd':unpack('>HHH',t['data'][:6]),'len':unpack('>H',t['data'][0][12:14])[0],'data':t['data'][0][14:],'error':unpack('>h',t['data'][0][6:8])[0],'errdetail':unpack('>h',t['data'][0][8:10])[0]}
      #if t['data'][x][6:12]==b'\x00'*6:
      #	t['data'][x]=[0,t["data"][x][12:]]
      #else:
      #	t['data'][x]=[unpack('>h',t["data"][x][6:8])[0],t["data"][x][12:]]
    else:
      return {"len":-1,'error':-1,'suberror':2}
  return t
