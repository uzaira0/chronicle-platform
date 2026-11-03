"""Shared command fixture for the complete shipped session probe."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CURL = r'''#!/usr/bin/env python3
import base64, hashlib, hmac, json, os, sys, time
a=sys.argv[1:]; mode=os.environ['RESPONSE_MODE']; url=a[-1]
if '--data-binary' in a: sys.stdin.read()
if mode=='unreachable': print('000',end=''); sys.exit(7)
if '-D' in a and a[a.index('-D')+1]!='-':
 headers=a[a.index('-D')+1]; body=a[a.index('-o')+1]
 status='404' if mode=='404' else '200'
 assert url.endswith('/chronicle/v3/auth/set-cookie'),url
 cookie='' if mode=='no-cookie' else 'Set-Cookie: chronicle_auth=synthetic; HttpOnly; '+('SameSite=None' if mode=='insecure' else 'Secure; SameSite=Lax')+'\r\n'
 open(headers,'w').write('HTTP/1.1 '+status+' OK\r\n'+cookie+'\r\n')
 open(body,'w').write('{"authenticated":true,"csrfToken":"synthetic-csrf"}')
 print(status,end='')
elif '-D' in a: print('HTTP/1.1 404 Not Found\r\n\r\n',end='')
elif url.endswith('/chronicle/v3/study'):
 headers=[a[i+1] for i,x in enumerate(a) if x=='-H']
 if '--cookie' in a:
  csrf='X-CSRF-Token: synthetic-csrf' in headers
  keyed=any(x.startswith('Idempotency-Key: ') for x in headers)
  status='200' if a[a.index('-X')+1]=='GET' else ('401' if not csrf else '400' if keyed else '428')
 else:
  token=next(x.removeprefix('Authorization: Bearer ') for x in headers if x.startswith('Authorization: Bearer '))
  segment=token.split('.')[1]
  payload=json.loads(base64.urlsafe_b64decode(segment+'='*(-len(segment)%4)))
  signed='.'.join(token.split('.')[:2]).encode()
  signature=base64.urlsafe_b64encode(hmac.new(os.environ['JWT_SECRET'].encode(),signed,hashlib.sha256).digest()).decode().rstrip('=')
  assert payload.get('sub')=='fixture-user' and payload.get('custom')=='preserved'
  valid=hmac.compare_digest(token.split('.')[2],signature) and payload.get('iss')=='fixture-issuer' and payload.get('aud')=='fixture-audience'
  status='200' if valid and payload['exp']>time.time() else '401'
  if valid and payload['exp']<=time.time(): status={'expiry-accepted':'200','expiry-throttled':'429'}.get(mode,status)
  if valid and payload['exp']>time.time() and mode=='valid-throttled': status='429'
  if mode=='rotation-current-rejected' and valid: status='401'
  if not valid and payload['exp']>time.time():
   status={'rotation-old-accepted':'200','rotation-forbidden':'403','rotation-throttled':'429'}.get(mode,status)
 print(status,end='')
else: print('200' if url.endswith('/chronicle/v3/auth/session') or url.endswith('/chronicle/v3/') else '401',end='')
'''


def run_session_probe(mode, signing_key='synthetic-secret'):
    with tempfile.TemporaryDirectory() as directory:
        command = Path(directory) / 'curl'
        command.write_text(CURL)
        command.chmod(0o755)
        claims = {'sub': 'fixture-user', 'iss': 'fixture-issuer', 'aud': 'fixture-audience',
                  'custom': 'preserved', 'exp': 4102444800}
        encoded = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        signing = encoded({'alg': 'HS256', 'typ': 'JWT'}) + '.' + encoded(claims)
        signature = base64.urlsafe_b64encode(hmac.new(b'synthetic-secret', signing.encode(), hashlib.sha256).digest()).decode().rstrip('=')
        return subprocess.run(['bash', str(ROOT / 'tests/security/session-management-tests.sh')],
            env=dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'], BASE_URL='https://fixture.invalid',
                     AUTH_TOKEN=signing + '.' + signature, JWT_SECRET=signing_key,
                     OLD_JWT_SECRET='synthetic-retired', NEW_JWT_SECRET='synthetic-secret', RESPONSE_MODE=mode),
            capture_output=True, text=True, timeout=30)
