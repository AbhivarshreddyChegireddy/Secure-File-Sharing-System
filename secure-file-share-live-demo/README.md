# Secure File Sharing System — Zero-Dependency Demo

This version needs **only a JDK** — no Maven, no internet access, no dependencies to download.
It uses the JDK's built-in `com.sun.net.httpserver` and `javax.crypto` only. I compiled and ran
this exact code in a live test before sending it to you (see the transcript for proof: register
→ upload → download → checksum match → raw ciphertext on disk → rejected bad tokens/passwords).

This is the fast way to *see it work right now*. For something closer to what you'd actually
ship (Spring Boot, JWT, envelope encryption, JPA/database, proper multipart uploads), use the
`secure-file-share` Maven project from earlier in our conversation — this demo trades some of
that production shape for "runs immediately with zero setup."

## Run it

```bash
cd live-demo/src
javac App.java
java App
```

You'll see:
```
Secure File Sharing System running on http://localhost:8080
```

## Try it (from another terminal)

```bash
# 1. Register
curl -s -X POST localhost:8080/api/auth/register -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"correct-horse-battery"}'
# => {"token":"...", "username":"alice"}

# 2. Upload a file (paste the token from step 1)
echo "hello world" > notes.txt
curl -s -X POST "localhost:8080/api/files/upload?filename=notes.txt&expiryMinutes=60&maxDownloads=5" \
  -H "Authorization: Bearer <token>" --data-binary @notes.txt
# => {"shareToken":"...", "shareUrl":"/api/share/...", ...}

# 3. Download via the share link — no login required
curl -s -o downloaded.txt "localhost:8080/api/share/<shareToken>"
diff notes.txt downloaded.txt   # identical

# 4. List your files
curl -s localhost:8080/api/files -H "Authorization: Bearer <token>"

# 5. Revoke a share link
curl -s -X DELETE localhost:8080/api/files/<shareToken> -H "Authorization: Bearer <token>"

# Optional: protect a link with an extra password
curl -s -X POST "localhost:8080/api/files/upload?filename=notes.txt&linkPassword=hunter2" \
  -H "Authorization: Bearer <token>" --data-binary @notes.txt
curl -s "localhost:8080/api/share/<shareToken>?password=hunter2"
```

## What's actually happening under the hood

- **AES-256-GCM** encrypts every file before it touches disk. Check `storage/` — the files
  are ciphertext, not your original bytes.
- **PBKDF2-HMAC-SHA256** (100,000 iterations, random salt) hashes passwords. Plaintext
  passwords are never stored.
- **256-bit random tokens** for both sessions and share links — unguessable, not sequential IDs.
- Share links enforce **expiry**, **max download count**, and an **optional extra password**,
  checked on every single request.
- **Path-traversal-safe** storage: uploaded files are saved under a random UUID, and the storage
  service refuses to resolve any path outside its root directory.
- **Constant-time comparison** for password hash checks (prevents timing attacks).

## Honest limitations of this specific version (fixed in the Spring version)

- **In-memory user/file database** — restarting the server wipes users and file metadata (the
  encrypted files stay on disk, but there's no record of them). Swap in a real DB for persistence.
- **In-memory master encryption key** — regenerated on every restart, so encrypted files from a
  previous run become unreadable after a restart. The Spring version derives this from a
  persistent configured secret instead.
- **No multipart form parsing** — upload takes the raw file body plus a `filename` query param,
  rather than a real `multipart/form-data` request. Simpler to implement without a framework,
  but not how a browser file-upload `<input>` would submit it directly.
- **Sessions never expire** in this demo (no TTL check) — add one before using this beyond a demo.
- Single process, single machine — no horizontal scaling story.

None of these are hard to fix; they're just the corners I cut to get you something that runs
immediately with zero setup. Happy to add persistence (SQLite, still zero-dependency) or a
real multipart parser next if you want to keep going with this version specifically.
