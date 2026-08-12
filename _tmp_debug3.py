import app, base64, json, re
c = app.app.test_client()

def csrf(p):
    m = re.search(rb'<meta name="csrf-token" content="([^"]+)"', p)
    return m.group(1).decode() if m else None

tok = csrf(c.get('/encrypt').data)
print('encrypt CSRF:', bool(tok))
r = c.get('/api/keys/generate-aes')
d = r.get_json() or {}
key = d.get('key', ''); iv = d.get('iv', '')
print('Generated AES key b64 len:', len(base64.b64decode(key)), 'bytes, iv len:', len(base64.b64decode(iv)), 'bytes')
payload = {'plaintext': 'Hello from integration test', 'key': key, 'iv': iv}
r = c.post('/api/encrypt/aes', data=json.dumps(payload),
           content_type='application/json', headers={'X-CSRFToken': tok})
print('POST /api/encrypt/aes:', r.status_code)
resp = r.get_json() or {}
print('  success:', resp.get('success'), '| error:', resp.get('error'))
ciphertext = resp.get('ciphertext', '')
print('  ciphertext len:', len(ciphertext))

r = c.get('/api/history/export?format=json')
data = json.loads(r.data) if r.status_code == 200 and r.data else []
print('History rows:', len(data) if isinstance(data, list) else 'N/A, type:', type(data).__name__)
if isinstance(data, list) and data:
    last = data[-1]
    print('  last row: op=' + str(last.get('operation')) +
          ' algo=' + str(last.get('algorithm')) +
          ' status=' + str(last.get('status')))
    print('  fields:', sorted(last.keys()))
