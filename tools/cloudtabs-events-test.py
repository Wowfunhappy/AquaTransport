import os
import select
import sys
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
from events import Channel,post
name='org.aquatransport.cloudtabs.test.%d'%os.getpid()
channel=Channel(name)
try:
    assert not select.select([channel.fd],[],[],0.05)[0]
    post(name)
    assert select.select([channel.fd],[],[],2)[0]
    channel.wait()
    assert not select.select([channel.fd],[],[],0.05)[0]
finally:channel.close()
print('PASS: native notification wakes the worker and drains without a refresh timer')
