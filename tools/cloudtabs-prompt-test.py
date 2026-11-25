from __future__ import print_function,unicode_literals
import os,sys,socket,threading,struct,json,subprocess
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
from compat import run
helper=os.path.abspath('build/stage/usr/share/aquatransport/cloudtabs/aquatransport-cloudtabs-authorize')
def test(arguments,accepted):
 parent,child=socket.socketpair();os.dup2(child.fileno(),198);child.close()
 os.environ['AQ_CLOUDTABS_UI_FD']='198'
 received=[]
 def read(size):
  value=b''
  while len(value)<size:
   part=parent.recv(size-len(value));assert part;value+=part
  return value
 def serve():
  request=json.loads(read(struct.unpack(b'!I',read(4))[0]));received.append(request)
  value=json.dumps({'accepted':accepted,'value':'135790' if accepted else ''}).encode('utf-8')
  parent.sendall(struct.pack(b'!I',len(value))+value)
 thread=threading.Thread(target=serve);thread.daemon=True;thread.start()
 try:
  payload=json.dumps({'title':'Device Passcode','message':'Enter the passcode for Fixture. Your passcode will not be saved.'}).encode('utf-8') if arguments==['--prompt'] else None
  result=run([helper]+arguments,input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,ui=True)
  thread.join(2);assert not thread.is_alive()
  assert result.returncode==(0 if accepted else 3),(result.returncode,result.stderr)
  assert len(received)==1
  assert received[0]['input']==(arguments==['--prompt'])
  assert not received[0]['hidden']
  if arguments==['--prompt'] and accepted:assert result.stdout==b'135790'
 finally:
  os.close(198);parent.close();os.environ.pop('AQ_CLOUDTABS_UI_FD',None)
for arguments in (['--prompt'],['--failure']):
 for accepted in (False,True):test(arguments,accepted)
print('PASS: inherited prompt socket, input visibility, accepted answers and cancellation; no standalone UI')
