# z0d1ak CTF 2026 — I Am Insecure

**Category:** Cryptography  
**Difficulty:** Medium  
**Points:** 216  
**Solves:** 30  
**Author:** TitanCode

---

## 1. Executive Summary

Challenge ini menyediakan dua endpoint: sebuah website sederhana dan service TCP yang meminta verifikasi identitas menggunakan kriptografi. Setelah melakukan directory fuzzing pada website, ditemukan bahwa file `.env` ter-expose ke publik dan berisi private key Ed25519 dalam format OpenSSH tanpa enkripsi. Vulnerability terjadi karena server tidak memblokir akses ke file konfigurasi sensitif. Dengan mengekstrak seed dari private key yang bocor, attacker dapat membuat Ed25519 signature yang valid atas nama pemilik key. Flag diperoleh dengan menandatangani string `"z0d1ak"` (nama team CTF) dan mengirimkan signature dalam format hex ke service TCP.

---

## 2. Challenge Description

> Edward is very insecure. Get the flag for him securely.

Flag format: `zdk{...}`

Endpoint yang diberikan:
- Website: `https://iaminsecure-key-<HASH>.chals.z0d1ak.org`
- Service: `ncat --ssl iaminsecure-<HASH>.chals.z0d1ak.org 1337`

---

## 3. Initial Reconnaissance

### 3.1 Service TCP

Pertama, connect ke service untuk memahami apa yang diminta:

```bash
ncat --ssl iaminsecure-ee1e4ca32eab.chals.z0d1ak.org 1337
```

Response:
```
Hi, My name is Edward XVI.
This is not a Secure Shell. How do I verify if you are legitimate?
What team are you trying to join?
Submit your answer:
```

Observasi penting:
- **"Edward XVI"** — hint ke algoritma **Ed25519** (EdDSA signature scheme berbasis Curve25519)
- **"not a Secure Shell"** — hint ke format SSH key
- **"verify if you are legitimate"** — server memverifikasi sesuatu (signature?)
- Service bersifat **one-shot**: menerima satu input, memvalidasi, dan memberikan response

Pengujian input random (`test`, `z0d1ak`, `flag`) selalu menghasilkan:
```
IMPOSTOR alert!!, you cannot join this team!
```

### 3.2 Website

```bash
curl -sk https://iaminsecure-key-ee1e4ca32eab.chals.z0d1ak.org/
```

Response: halaman kosong sederhana dari Python `http.server`. Hanya path `/` yang return 200, semua path lain return `not found`.

---

## 4. Attack Surface / Important Observations

1. Nama "Edward XVI" merujuk ke **Ed25519** — algoritma digital signature
2. Ed25519 signature bersifat **deterministic** — sama input = sama output (tidak ada random nonce)
3. Service tidak memberikan challenge/nonce per-koneksi — artinya jawaban yang benar bersifat **static**
4. Website sangat minimalis — kemungkinan ada file tersembunyi yang tidak di-index
5. Subdomain mengandung kata **"key"** (`iaminsecure-key-...`) — hint bahwa website menyimpan key

Hipotesis:
> Server memverifikasi Ed25519 signature. Private key bocor di suatu tempat pada website. Kita perlu menemukan key tersebut dan membuat signature yang valid.

---

## 5. Failed Attempts

### Attempt 1 — Submit plain text answers

Mencoba berbagai string sebagai jawaban langsung:
```
z0d1ak → IMPOSTOR
strangeThings → IMPOSTOR
EdwardXVI → IMPOSTOR
SHA256 fingerprint → IMPOSTOR
SSH public key line → IMPOSTOR
```

**Kesimpulan:** Jawaban bukan berupa teks biasa. Server mengharapkan format kriptografis tertentu.

### Attempt 2 — Structured formats (JSON, JWT, Base64)

```json
{"team":"z0d1ak","signature":"..."} → IMPOSTOR
```

JWT, Base64, hex encodings — semua menghasilkan IMPOSTOR.

**Kesimpulan:** Format jawaban sangat spesifik. Perlu menemukan key terlebih dahulu.

---

## 6. Vulnerability Discovery

### Expected Behavior

File `.env` seharusnya:
- Tidak dapat diakses dari web (blocked oleh web server configuration)
- Atau tidak ada di directory yang di-serve

### Actual Behavior

```bash
curl -sk https://iaminsecure-key-ee1e4ca32eab.chals.z0d1ak.org/.env
```

Response HTTP 200:
```
PRIVATE_KEY=b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA
MwAAAAtzc2gtZWQyNTUxOQAAACDPyOhez3umvslBCI5i8HiRMxV8610b6q3UUwng
sojUKwAAAJjW2NV61tjVegAAAAtzc2gtZWQyNTUxOQAAACDPyOhez3umvslBCI5i8
HiRMxV8610b6q3UUwngsojUKwAAAECdtHOYZwcfWGDqnai4dnyDO6gUttnFJ8wk5
2tUOrL9cM/I6F7Pe6a+yUEIjmLweJEzFXzrXRvqrdRTCeCyiNQrAAAAE3N0cmFuZ
2VUaGluZ3NAVGl0YW4BAg==
```

### Root Cause

Web server (Python `http.server`) melayani **semua file** di dalam directory termasuk `.env`. Tidak ada konfigurasi untuk memblokir akses ke file sensitif.

Private key disimpan tanpa enkripsi (`cipher: none`, `kdf: none`), sehingga siapapun yang mendapatkan file ini langsung memiliki akses penuh ke key material.

---

## 7. Exploitation

### Step 1: Decode base64 dan parse format OpenSSH

Base64 tersebut men-decode ke format `openssh-key-v1`:

```
Magic:    openssh-key-v1\0
Cipher:   none (tidak dienkripsi)
KDF:      none
Key type: ssh-ed25519
Comment:  strangeThings@Titan
Seed:     9db4739867071f5860ea9da8b8767c833ba814b6d9c527cc24e76b543ab2fd70
```

### Step 2: Reconstruct Ed25519 private key dari seed

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

seed = bytes.fromhex("9db4739867071f5860ea9da8b8767c833ba814b6d9c527cc24e76b543ab2fd70")
private_key = Ed25519PrivateKey.from_private_bytes(seed)
```

### Step 3: Sign team name "z0d1ak"

```python
signature = private_key.sign(b"z0d1ak")
answer = signature.hex()
# Result: 1a29ac83724abf979c944005805f98a7d497bd10d85c7ca097d7311c85a7b453...
```

### Step 4: Submit ke service

```
Submit your answer:
1a29ac83724abf979c944005805f98a7d497bd10d85c7ca097d7311c85a7b45367248a7b86692cecbb55a5d557b282baa233337ec84a09e16071ba06999e0f0e
```

Response:
```
Welcome: the flag is zdk{You_Are_SO_5ecurE_WitH_4_PrIva7e_dYnAMIC_IN5Tance}
```

**Kenapa ini bekerja:**

Server menyimpan public key yang sesuai. Saat menerima jawaban, server:
1. Menginterpretasikan input sebagai hex-encoded Ed25519 signature
2. Memverifikasi signature tersebut terhadap message `"z0d1ak"` menggunakan stored public key
3. Jika signature valid → user membuktikan kepemilikan private key → berikan flag

Karena kita memiliki private key yang bocor, kita dapat membuat signature yang valid.

---

## 8. Root Cause Analysis

Vulnerability **bukan** terletak pada kelemahan algoritma Ed25519 (yang merupakan state-of-the-art signature scheme).

Root cause sebenarnya adalah **information disclosure**:
1. File `.env` berisi private key tanpa enkripsi
2. Web server tidak memblokir akses ke file dot-files
3. Private key tidak dilindungi passphrase

Bahkan jika file dipindahkan ke lokasi lain, vulnerability tetap ada selama:
- Private key tersimpan tanpa enkripsi
- Tidak ada access control pada file tersebut
- Key tidak di-rotate setelah compromise

---

## 9. Exploit Automation

```python
"""
I Am Insecure - Automated Solver
Requirements: pip install cryptography
Usage: python solve_iaminsecure.py
"""
import socket, ssl, base64, struct, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# === CONFIG ===
INSTANCE_HASH = "ee1e4ca32eab"  # Ganti dengan hash instance kamu

KEY_HOST = f"iaminsecure-key-{INSTANCE_HASH}.chals.z0d1ak.org"
SERVICE_HOST = f"iaminsecure-{INSTANCE_HASH}.chals.z0d1ak.org"

# Step 1: Retrieve leaked .env
ctx = ssl._create_unverified_context()
req = urllib.request.Request(f"https://{KEY_HOST}/.env")
env_content = urllib.request.urlopen(req, context=ctx).read().decode()
print(f"[+] Retrieved .env from {KEY_HOST}")

# Step 2: Parse OpenSSH private key
key_b64 = env_content.split("PRIVATE_KEY=")[1].replace("\n", "").strip()
blob = base64.b64decode(key_b64)

def read_str(data, offset):
    length = struct.unpack(">I", data[offset:offset+4])[0]
    return data[offset+4:offset+4+length], offset+4+length

offset = 15  # Skip "openssh-key-v1\0"
for _ in range(3): _, offset = read_str(blob, offset)  # cipher, kdf, kdf_opts
offset += 4  # num_keys
_, offset = read_str(blob, offset)  # pub blob
priv_blob, _ = read_str(blob, offset)

priv_offset = 8  # Skip check ints
for _ in range(2): _, priv_offset = read_str(priv_blob, priv_offset)  # type, pub
secret, _ = read_str(priv_blob, priv_offset)
seed = secret[:32]
print(f"[+] Extracted Ed25519 seed: {seed.hex()[:16]}...")

# Step 3: Sign "z0d1ak"
private_key = Ed25519PrivateKey.from_private_bytes(seed)
signature = private_key.sign(b"z0d1ak")
print(f"[+] Signature: {signature.hex()[:32]}...")

# Step 4: Submit to service
raw = socket.create_connection((SERVICE_HOST, 1337), timeout=15)
s = ssl._create_unverified_context().wrap_socket(raw, server_hostname=SERVICE_HOST)
s.settimeout(3)
try:
    while True:
        if not s.recv(4096): break
except socket.timeout: pass

s.sendall(signature.hex().encode() + b"\n")
s.settimeout(3)
response = b""
try:
    while True:
        d = s.recv(4096)
        if not d: break
        response += d
except socket.timeout: pass
s.close()

print(f"[+] Response: {response.decode().strip()}")
```

Script melakukan seluruh attack chain secara otomatis: retrieve `.env`, parse key, sign, dan submit.

---

## 10. Flag

```
zdk{You_Are_SO_5ecurE_WitH_4_PrIva7e_dYnAMIC_IN5Tance}
```

---

## 11. Attack Chain

```
Directory Fuzzing pada Website
        |
        v
Menemukan /.env (Information Disclosure)
        |
        v
Extract base64-encoded OpenSSH private key
        |
        v
Parse openssh-key-v1 format, extract 32-byte seed
        |
        v
Reconstruct Ed25519 private key
        |
        v
Sign team name "z0d1ak" (deterministic signature)
        |
        v
Submit hex-encoded signature ke TCP service
        |
        v
Server verifies signature -> Flag
```

---

## 12. Why The Exploit Works

Server memverifikasi Ed25519 signature menggunakan public key yang disimpan internal. Karena:

1. Private key **bocor** melalui file `.env` yang tidak diproteksi
2. Private key **tidak dienkripsi** (cipher=none) sehingga langsung usable
3. Ed25519 signature bersifat **deterministic** — tidak perlu timing atau session-specific data
4. Server memverifikasi signature atas **fixed message** (`"z0d1ak"`) — tidak ada challenge-response yang berubah

Siapapun yang memiliki private key dapat membuat signature valid kapanpun.

---

## 13. How To Fix It

### Vulnerable Implementation:
```python
# Web server menyajikan semua file termasuk .env
http.server.SimpleHTTPServer(directory="/app")
```

### Perbaikan:

```python
# 1. Block akses ke dot-files di web server config
# Nginx example:
location ~ /\. {
    deny all;
    return 404;
}

# 2. Encrypt private key with passphrase
ssh-keygen -t ed25519 -f id_ed25519  # Selalu set passphrase!

# 3. Gunakan environment variables, bukan .env file di served directory
export PRIVATE_KEY="..."

# 4. Jika harus pakai .env, letakkan di LUAR webroot
/opt/secrets/.env    # Bukan di /var/www/html/.env
```

### Defense-in-depth:
- Jangan pernah menyimpan private key tanpa enkripsi
- Selalu block akses ke file dot (`.env`, `.git`, `.htaccess`)
- Gunakan secret management tools (Vault, AWS Secrets Manager)
- Implementasikan challenge-response protocol, bukan static verification
- Rotate keys secara berkala

---

## 14. Key Takeaways

1. **File `.env` adalah salah satu target utama attacker** — selalu pastikan tidak ter-expose via web
2. **Private key tanpa passphrase = plaintext credential** — siapapun yang membaca file memiliki akses penuh
3. **Naming hint dalam CTF penting** — "Edward XVI" langsung merujuk ke Ed25519
4. **Deterministic signatures tanpa challenge-response = replayable** — leaked key = permanent compromise
5. **Directory fuzzing adalah reconnaissance standard** — selalu cek common files (`.env`, `.git/`, `robots.txt`)

---

## 15. Reproduction Steps

```bash
# 1. Clone solver
cd C:\Users\rangk\Downloads\iaminsecure

# 2. Install dependency
pip install cryptography

# 3. Edit INSTANCE_HASH di solve_iaminsecure.py sesuai instance kamu

# 4. Run solver
python solve_iaminsecure.py
```

Expected output:
```
[+] Retrieved .env from iaminsecure-key-ee1e4ca32eab.chals.z0d1ak.org
[+] Extracted Ed25519 seed: 9db4739867071f58...
[+] Signature: 1a29ac83724abf97...
[+] Response: Welcome: the flag is zdk{You_Are_SO_5ecurE_WitH_4_PrIva7e_dYnAMIC_IN5Tance}
```

**Dependencies:**
- Python 3.10+
- `cryptography` library (pip install cryptography)

---

## 16. Timeline

```
00:00  Read challenge, connect ke service, observasi banner "Edward XVI"
00:05  Identifikasi hint Ed25519, test input plain text → semua IMPOSTOR
00:15  Directory fuzzing pada website → ditemukan /.env
00:18  Extract dan parse OpenSSH private key
00:22  Sign "z0d1ak" dengan leaked key, submit hex signature
00:23  Flag obtained
```
