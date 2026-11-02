import os
import sys
import time
import paramiko
import urllib.request
import ssl

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

HOST = "185.219.7.154"
USER = "root"
PASS = "K9yh3CsS"
REMOTE_DIR = "/opt/cipher"

print(f"Connecting to {HOST} via SSH...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS, timeout=20)
print("Connected successfully!")

sftp = ssh.open_sftp()
print("SFTP session opened.")

files_to_upload = [
    ("CIPHER.apk", f"{REMOTE_DIR}/CIPHER.apk"),
    ("public/app.js", f"{REMOTE_DIR}/public/app.js"),
    ("public/styles.css", f"{REMOTE_DIR}/public/styles.css"),
    ("public/tunnel.json", f"{REMOTE_DIR}/public/tunnel.json"),
    ("public/index.html", f"{REMOTE_DIR}/public/index.html"),
    ("server/server.js", f"{REMOTE_DIR}/server/server.js"),
]

for local_path, remote_path in files_to_upload:
    if os.path.exists(local_path):
        size = os.path.getsize(local_path)
        print(f"Uploading {local_path} ({size} bytes) -> {remote_path}...")
        sftp.put(local_path, remote_path)
        print(f"Uploaded {local_path} successfully.")
    else:
        print(f"Warning: {local_path} not found locally.")

sftp.close()
print("SFTP finished.")

print("Restarting cipher.service...")
stdin, stdout, stderr = ssh.exec_command("systemctl restart cipher.service && systemctl status cipher.service --no-pager")
out = stdout.read().decode('utf-8', errors='replace')
err = stderr.read().decode('utf-8', errors='replace')
print(out)
if err:
    print("Stderr:", err)

print("Checking remote files...")
stdin, stdout, stderr = ssh.exec_command(f"ls -lh {REMOTE_DIR}/CIPHER.apk {REMOTE_DIR}/public/app.js")
print(stdout.read().decode('utf-8', errors='replace'))

ssh.close()
print("SSH connection closed.")

# Verify via HTTPS and WSS
print("\nVerifying public web endpoints...")
ctx = ssl.create_default_context()

try:
    req = urllib.request.Request("https://fotowaqu.ru/download", headers={"User-Agent": "CIPHER-Updater/1.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        print(f"GET https://fotowaqu.ru/download: Status {resp.status}")
        headers = dict(resp.getheaders())
        print(f"Content-Type: {headers.get('Content-Type')}")
        print(f"Content-Length: {headers.get('Content-Length')}")
        print(f"Content-Disposition: {headers.get('Content-Disposition')}")
except Exception as e:
    print(f"Download verification error: {e}")

try:
    req = urllib.request.Request("https://fotowaqu.ru/tunnel.json", headers={"User-Agent": "CIPHER-Updater/1.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        content = resp.read().decode('utf-8')
        print(f"GET https://fotowaqu.ru/tunnel.json: Status {resp.status}, Content: {content}")
except Exception as e:
    print(f"tunnel.json verification error: {e}")
