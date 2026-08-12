import re, uuid, json
import app

c = app.app.test_client()

def get_csrf(page_bytes):
    m = re.search(rb'<meta name="csrf-token" content="([^"]+)"', page_bytes)
    return m.group(1).decode() if m else None

print("=== 1) Register a new user ===")
user = 'testuser_' + uuid.uuid4().hex[:6]
pwd = 'StrongPass123!'
r = c.get('/register')
tok = get_csrf(r.data)
print('CSRF token present on /register:', bool(tok))
r = c.post('/register',
           data={'username': user, 'display_name': 'Test User',
                 'password': pwd, 'confirm_password': pwd},
           headers={'X-CSRFToken': tok}, follow_redirects=False)
print('POST /register:', r.status_code, '| redirect:', r.headers.get('Location'))

print("\n=== 2) Login as that user ===")
r = c.get('/login')
tok = get_csrf(r.data)
r2 = c.post('/login', data={'username': user, 'password': pwd},
            headers={'X-CSRFToken': tok}, follow_redirects=False)
print('POST /login user:', r2.status_code, '| redirect:', r2.headers.get('Location'))
print("\n=== 3) History page for logged-in regular user ===")
r3 = c.get('/history')
print('GET /history (user):', r3.status_code)
print('  has YOUR LOGS header:', b'YOUR LOGS' in r3.data)
print('  has PURGE LOG (ADMIN):', b'PURGE LOG (ADMIN)' in r3.data)

print("\n=== 4) Logout user ===")
r = c.get('/logout', follow_redirects=False)
print('GET /logout:', r.status_code)

print("\n=== 5) Admin login via /admin/login ===")
r = c.get('/admin/login')
tok = get_csrf(r.data)
print('CSRF on /admin/login:', bool(tok))
r = c.post('/admin/login', data={'username': 'admin', 'password': 'ENCRYPTSYS112'},
           headers={'X-CSRFToken': tok}, follow_redirects=False)
print('POST /admin/login admin:', r.status_code, '| redirect:', r.headers.get('Location'))

print("\n=== 6) Admin dashboard ===")
r = c.get('/admin')
print('GET /admin (dashboard):', r.status_code, '| len:', len(r.data))

print("\n=== 7) Admin users API ===")
r = c.get('/api/admin/users')
print('GET /api/admin/users:', r.status_code)
d = r.get_json()
print('  success:', d and d.get('success'),
      '| n_users:', len((d or {}).get('users', [])))

print("\n=== 8) Admin history page ===")
r = c.get('/history')
print('GET /history (admin):', r.status_code)
print('  has ADMIN VIEW header:', b'ADMIN VIEW' in r.data)
print('  has PURGE LOG (ADMIN) button:', b'PURGE LOG (ADMIN)' in r.data)

print("\n=== 9) Games complete API with crazy_mode ===")
r = c.get('/games')  # get CSRF
tok = get_csrf(r.data)
payload = {'game_id': 'crazy_mode', 'won': True, 'xp': 2100, 'score': 5500}
r = c.post('/api/games/complete',
           data=json.dumps(payload),
           content_type='application/json',
           headers={'X-CSRFToken': tok})
print('POST /api/games/complete (crazy_mode won):', r.status_code)
d = r.get_json()
print('  success:', d and d.get('success'),
      '| rank:', (d and d.get('statistics') or {}).get('rank', {}).get('name'),
      '| best_score_game:', (d and d.get('statistics') or {}).get('best_score_game'))

print("\n=== 10) Encrypt AES operation (writes history with ownership fields) ===")
import os
os.environ['FLASK_ENV'] = 'test'  # avoid dev-mode quirks
r = c.get('/encrypt')
tok = get_csrf(r.data)
print('Encrypt page CSRF present:', bool(tok))
# AES encrypt via the actual API route
payload = {
    'plaintext': 'Hello from integration test',
    'key': '0123456789abcdef0123456789abcdef',  # 32 hex chars = 256 bits
    'iv': '0123456789abcdef0123456789abcd',     # 32 hex chars = 128 bits
}
r = c.post('/api/encrypt/aes',
           data=json.dumps(payload),
           content_type='application/json',
           headers={'X-CSRFToken': tok})
print('POST /api/encrypt/aes status:', r.status_code)
d = r.get_json()
print('  success:', d and d.get('success'), '| ciphertext len:', len((d or {}).get('ciphertext') or ''))

# Inspect latest history row via JSON export
r = c.get('/api/history/export?format=json')
print('GET /api/history/export?format=json:', r.status_code)
if r.status_code == 200:
    data = json.loads(r.data) if r.data else []
    if data:
        last = data[-1]
        keys = sorted(last.keys())
        print('  last history entry fields (' + str(len(keys)) + '):', keys)
        print('  operation=', last.get('operation'),
              '| algorithm=', last.get('algorithm'),
              '| status=', last.get('status'),
              '| owner_username=', repr(last.get('owner_username')),
              '| storage=', last.get('storage'))

print("\n=== ALL TESTS DONE ===")
