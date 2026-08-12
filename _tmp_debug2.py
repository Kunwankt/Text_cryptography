import re, uuid, json
import app

c = app.app.test_client()

def get_csrf(page_bytes):
    m = re.search(rb'<meta name="csrf-token" content="([^"]+)"', page_bytes)
    return m.group(1).decode() if m else None

print("=== 1) Register & login user (clean - no pre-existing session ===")
c2 = app.app.test_client()  # fresh client
user = 'tu_' + uuid.uuid4().hex[:6]
pwd = 'StrongPass123!'

r = c2.get('/register')
tok = get_csrf(r.data)
r = c2.post('/register',
            data={'username': user, 'display_name': 'Test',
                  'password': pwd, 'confirm_password': pwd},
            headers={'X-CSRFToken': tok}, follow_redirects=False)
print('POST /register:', r.status_code, 'redirect:', r.headers.get('Location'))

r = c2.get('/logout', follow_redirects=False)
print('logout:', r.status_code)

r = c2.get('/login')
tok = get_csrf(r.data)
print('CSRF from /login:', bool(tok))
r2 = c2.post('/login', data={'username': user, 'password': pwd},
              headers={'X-CSRFToken': tok}, follow_redirects=False)
print('POST /login user:', r2.status_code, '| redirect:', r2.headers.get('Location'))
if r2.status_code != 302:
    print('  Response (trimmed):', r2.data[:800])

print("\n=== 2) AES encryption API — check what AES route expects ===")
r = c2.get('/encrypt')
tok = get_csrf(r.data)
print("App page:", r.status_code)
r = c2.post('/api/encrypt/aes',
            data=json.dumps({'plaintext': 'Hello test',
                             'key': '0123456789abcdef0123456789abcdef',
                             'iv': '0123456789abcdef0123456789abcd'}),
            content_type='application/json',
            headers={'X-CSRFToken': tok})
print("POST /api/encrypt/aes status:", r.status_code)
import json as _json_mod
d = r.get_json()
print('  body:', _json_mod.dumps(d or {})[:500])
