import os, json, time, sqlite3, secrets, base64, io, socket, threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response, stream_with_context, send_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

DB_PATH = 'messenger.db'
os.makedirs('uploads', exist_ok=True)

# ── In-memory queues ──────────────────────────────────────────────────────────
# One lock, two separate queues: chat events and call signals.
# Call signals get their own queue so they're never delayed by chat SSE polling.
_lock        = threading.Lock()
_chat_q      = {}   # username -> list[str]   (SSE events for messages)
_call_q      = {}   # username -> list[str]   (call signals, polled separately)
_call_event  = {}   # username -> threading.Event  (wake long-poll instantly)

def _ensure(u):
    if u not in _chat_q:   _chat_q[u]   = []
    if u not in _call_q:   _call_q[u]   = []
    if u not in _call_event: _call_event[u] = threading.Event()

def push_chat(username, data):
    with _lock:
        _ensure(username)
        _chat_q[username].append(json.dumps(data))

def push_call(username, data):
    with _lock:
        _ensure(username)
        _call_q[username].append(json.dumps(data))
        _call_event[username].set()   # wake any waiting long-poll instantly

def pop_chat(username):
    with _lock:
        msgs = list(_chat_q.get(username, []))
        _chat_q[username] = []
    return msgs

def pop_call(username):
    with _lock:
        msgs = list(_call_q.get(username, []))
        _call_q[username] = []
    return msgs

# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                enc_key TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                msg_type TEXT DEFAULT 'text',
                file_name TEXT,
                file_mime TEXT,
                duration TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
        """)

# ── Crypto ────────────────────────────────────────────────────────────────────
_master = None
def get_master():
    global _master
    if _master: return _master
    path = 'server_secret.key'
    _master = open(path,'rb').read() if os.path.exists(path) else secrets.token_bytes(32)
    if not os.path.exists(path): open(path,'wb').write(_master)
    return _master

def conv_key(a, b):
    pair = '|'.join(sorted([a.lower(), b.lower()])).encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=get_master(), iterations=100000)
    return kdf.derive(pair)

def encrypt(data, a, b):
    nonce = os.urandom(12)
    ct = AESGCM(conv_key(a,b)).encrypt(nonce, data if isinstance(data,bytes) else data.encode(), None)
    return {'ciphertext': base64.b64encode(ct).decode(), 'nonce': base64.b64encode(nonce).decode()}

def decrypt(ct_b64, nonce_b64, a, b):
    return AESGCM(conv_key(a,b)).decrypt(base64.b64decode(nonce_b64), base64.b64decode(ct_b64), None)

def hash_pw(pw, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=50000)
    return base64.b64encode(kdf.derive(pw.encode())).decode()

def get_token():
    return request.headers.get('X-Auth-Token','') or request.args.get('token','')

def current_user():
    t = get_token()
    if not t: return None
    with get_db() as conn:
        row = conn.execute("SELECT username,expires_at FROM sessions WHERE token=?", (t,)).fetchone()
        if row and datetime.fromisoformat(row['expires_at']) > datetime.utcnow():
            return row['username']
    return None

# ── Init (runs on gunicorn import too, not just __main__) ─────────────────────
init_db()
get_master()

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route('/api/signup', methods=['POST'])
def signup():
    d = request.json
    u, p = d.get('username','').strip().lower(), d.get('password','')
    if not u or not p: return jsonify({'error':'Username and password required'}), 400
    if len(u) < 3 or len(u) > 24: return jsonify({'error':'Username must be 3-24 chars'}), 400
    if len(p) < 6: return jsonify({'error':'Password must be at least 6 characters'}), 400
    salt = secrets.token_hex(16)
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO users (username,password_hash,salt,enc_key,created_at) VALUES(?,?,?,?,?)",
                (u, hash_pw(p,salt), salt, base64.b64encode(os.urandom(32)).decode(), datetime.utcnow().isoformat()))
    except sqlite3.IntegrityError:
        return jsonify({'error':'Username already taken'}), 409
    return jsonify({'success':True})

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json
    u, p = d.get('username','').strip().lower(), d.get('password','')
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    if not user or not secrets.compare_digest(hash_pw(p,user['salt']), user['password_hash']):
        return jsonify({'error':'Invalid credentials'}), 401
    t = secrets.token_hex(32)
    with get_db() as conn:
        conn.execute("INSERT INTO sessions (token,username,expires_at) VALUES(?,?,?)",
            (t, u, (datetime.utcnow()+timedelta(days=7)).isoformat()))
    return jsonify({'success':True, 'token':t, 'username':u})

@app.route('/api/logout', methods=['POST'])
def logout():
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (get_token(),))
    return jsonify({'success':True})

# ── Users ─────────────────────────────────────────────────────────────────────
@app.route('/api/users')
def list_users():
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    with get_db() as conn:
        rows = conn.execute("SELECT username FROM users WHERE username!=? ORDER BY username",(u,)).fetchall()
    return jsonify({'users':[r['username'] for r in rows]})

# ── Messages ──────────────────────────────────────────────────────────────────
@app.route('/api/messages/<peer>')
def get_messages(peer):
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) ORDER BY timestamp",
            (u,peer,peer,u)).fetchall()
    result = []
    for r in rows:
        try: content = decrypt(r['ciphertext'],r['nonce'],u,peer).decode('utf-8')
        except: content = '[decryption error]'
        result.append({'id':r['id'],'sender':r['sender'],'content':content,
            'msg_type':r['msg_type'],'file_name':r['file_name'],
            'file_mime':r['file_mime'],'timestamp':r['timestamp']})
    return jsonify({'messages':result})

@app.route('/api/messages/<peer>', methods=['POST'])
def send_message(peer):
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    text = request.json.get('text','').strip()
    if not text: return jsonify({'error':'Empty message'}), 400
    e = encrypt(text, u, peer)
    ts = datetime.utcnow().isoformat()
    with get_db() as conn:
        cur = conn.execute("INSERT INTO messages (sender,recipient,ciphertext,nonce,msg_type,timestamp) VALUES(?,?,?,?,?,?)",
            (u,peer,e['ciphertext'],e['nonce'],'text',ts))
        mid = cur.lastrowid
    push_chat(peer, {'type':'message','sender':u,'content':text,'msg_type':'text','timestamp':ts})
    return jsonify({'success':True,'msg_id':mid,'timestamp':ts})

# ── Files ─────────────────────────────────────────────────────────────────────
@app.route('/api/upload/<peer>', methods=['POST'])
def upload_file(peer):
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    if 'file' not in request.files: return jsonify({'error':'No file'}), 400
    f = request.files['file']
    fname = secure_filename(f.filename) or 'file'
    mime = f.content_type or 'application/octet-stream'
    e = encrypt(f.read(), u, peer)
    ts = datetime.utcnow().isoformat()
    with get_db() as conn:
        is_voice = request.args.get('voice')=='1'
        duration = request.args.get('duration','')
        final_type = 'voice' if is_voice else 'file'
        cur = conn.execute(
            "INSERT INTO messages (sender,recipient,ciphertext,nonce,msg_type,file_name,file_mime,duration,timestamp) VALUES(?,?,?,?,?,?,?,?,?)",
            (u,peer,e['ciphertext'],e['nonce'],final_type,fname,mime,duration,ts))
        mid = cur.lastrowid
    is_voice = request.args.get('voice')=='1'
    duration = request.args.get('duration','')
    final_type = 'voice' if is_voice else 'file'
    push_chat(peer, {'type':'message','sender':u,'content':str(mid),'msg_type':final_type,
        'file_name':fname,'file_mime':mime,'msg_id':mid,'duration':duration,'timestamp':ts})
    return jsonify({'success':True,'msg_id':mid,'timestamp':ts})

@app.route('/api/file/<int:msg_id>')
def download_file(msg_id):
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    with get_db() as conn:
        row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row or (row['sender']!=u and row['recipient']!=u):
        return jsonify({'error':'Not found'}), 404
    other = row['recipient'] if row['sender']==u else row['sender']
    try: data = decrypt(row['ciphertext'],row['nonce'],u,other)
    except Exception as ex:
        return jsonify({'error':'Decryption failed'}), 500
    return send_file(io.BytesIO(data), download_name=row['file_name'], mimetype=row['file_mime'], as_attachment=True)

# ── Call signal — push to dedicated call queue ────────────────────────────────
@app.route('/api/call/signal', methods=['POST'])
def call_signal():
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    d = request.json
    peer = d.get('peer')
    if not peer: return jsonify({'error':'No peer'}), 400
    push_call(peer, {
        'type': 'call_signal',
        'from': u,
        'signal_type': d.get('signal_type'),
        'payload': d.get('payload', {})
    })
    return jsonify({'success':True})

# ── Call poll — long-poll endpoint, wakes instantly when signal arrives ────────
# This is completely separate from SSE so Flask's threading can't deadlock it.
@app.route('/api/call/poll')
def call_poll():
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    with _lock:
        _ensure(u)
    # Return any already-queued signals immediately
    signals = pop_call(u)
    if signals:
        return jsonify({'signals': [json.loads(s) for s in signals]})
    # Otherwise wait up to 25 seconds for a signal
    _call_event[u].clear()
    fired = _call_event[u].wait(timeout=25)
    if fired:
        signals = pop_call(u)
    return jsonify({'signals': [json.loads(s) for s in signals]})

# ── SSE — chat messages only, simple polling ──────────────────────────────────
@app.route('/api/events')
def events():
    u = current_user()
    if not u: return jsonify({'error':'Unauthorized'}), 401
    def stream():
        with _lock: _ensure(u); _chat_q[u] = []
        try:
            yield f"data: {json.dumps({'type':'connected','username':u})}\n\n"
            while True:
                msgs = pop_chat(u)
                if msgs:
                    for m in msgs:
                        yield f"data: {m}\n\n"
                else:
                    yield ": ping\n\n"
                time.sleep(0.3)
        except GeneratorExit:
            pass
    return Response(stream_with_context(stream()), mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Connection':'keep-alive'})

# ── Service worker ────────────────────────────────────────────────────────────
@app.route('/sw.js')
def sw():
    js = """
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('push',e=>{
    const d=e.data?e.data.json():{};
    e.waitUntil(self.registration.showNotification(d.title||'CipherTalk',{
        body:d.body||'New message',icon:'/static/icon.png',badge:'/static/icon.png',
        tag:d.tag||'msg',renotify:true,vibrate:[200,100,200],data:{url:d.url||'/'}
    }));
});
self.addEventListener('notificationclick',e=>{
    e.notification.close();
    e.waitUntil(clients.matchAll({type:'window'}).then(cs=>{
        const c=cs[0];
        if(c){c.focus();c.postMessage({type:'notifclick',data:e.notification.data});}
        else clients.openWindow(e.notification.data.url||'/');
    }));
});
"""
    return Response(js, mimetype='application/javascript',
        headers={'Service-Worker-Allowed':'/','Cache-Control':'no-cache'})

@app.route('/static/icon.png')
@app.route('/favicon.ico')
def icon():
    png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')
    return Response(png, mimetype='image/png')

@app.route('/')
def index():
    import gzip as _gz
    html = open(os.path.join(os.path.dirname(__file__), 'templates', 'index.html'), encoding='utf-8').read()
    ae = request.headers.get('Accept-Encoding','')
    if 'gzip' in ae:
        data = _gz.compress(html.encode(), compresslevel=6)
        return Response(data, mimetype='text/html',
            headers={'Content-Encoding':'gzip','Vary':'Accept-Encoding','Cache-Control':'no-store'})
    return html

if __name__ == '__main__':
    init_db(); get_master()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8',80)); local_ip=s.getsockname()[0]; s.close()
    except: local_ip='127.0.0.1'
    has_ssl = os.path.exists('cert.pem') and os.path.exists('key.pem')
    if has_ssl:
        import ssl; ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain('cert.pem','key.pem'); proto='https'
    else:
        ctx=None; proto='http'
    print(f"\n🔐 CipherTalk  →  {proto}://{local_ip}:5000\n")
    app.run(debug=False, threaded=True, host='0.0.0.0', port=5000, ssl_context=ctx)
