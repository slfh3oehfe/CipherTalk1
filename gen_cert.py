"""
CipherTalk — SSL Certificate Generator
Run once: python gen_cert.py
This generates cert.pem + key.pem so calls work on mobile.
"""
import socket, datetime, ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def get_ips():
    ips = {'127.0.0.1', 'localhost'}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ips.add(s.getsockname()[0])
        s.close()
    except: pass
    # Also try getting all local addresses
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ':' not in addr:  # IPv4 only
                ips.add(addr)
    except: pass
    return list(ips)

print("🔐 Generating SSL certificate for CipherTalk...")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ips = get_ips()
print(f"   Including IPs: {', '.join(ips)}")

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"CipherTalk"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CipherTalk Local"),
])

san = []
for ip in ips:
    try:
        san.append(x509.IPAddress(ipaddress.IPv4Address(ip)))
    except: pass
san.append(x509.DNSName(u"localhost"))

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.SubjectAlternativeName(san), critical=False)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)

with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
with open("key.pem", "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    local_ip = s.getsockname()[0]
    s.close()
except:
    local_ip = '192.168.x.x'

print(f"""
✅ cert.pem and key.pem generated!

Now restart: python app.py
Then on your phone open: https://{local_ip}:5000

HOW TO ACCEPT THE SECURITY WARNING:

  Android Chrome:
    Tap "Advanced" → "Proceed to {local_ip} (unsafe)"

  iPhone Safari:
    1. Tap "Show Details" → "visit this website" → "Visit Website"
    2. Go to: Settings → General → VPN & Device Management
       → find CipherTalk cert → tap "Trust"
    3. Then: Settings → General → About → Certificate Trust Settings
       → toggle CipherTalk ON

  Firefox (any device):
    Click "Advanced" → "Accept the Risk and Continue"
""")