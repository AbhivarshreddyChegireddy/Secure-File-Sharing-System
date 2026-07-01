import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Secure File Sharing System — zero external dependencies.
 * Uses only the JDK's built-in HTTP server and javax.crypto, so it compiles and runs with
 * nothing but a JDK (no Maven, no internet access needed to fetch libraries).
 *
 * Run:   javac App.java && java App
 * Then:  see the printed curl examples, or README.md in this folder.
 *
 * Security model (same principles as the full Spring version, simplified for a single file):
 *  - AES-256-GCM authenticated encryption for every stored file, random IV per file.
 *  - PBKDF2-HMAC-SHA256 password hashing (salted, 100k iterations) — no plaintext passwords stored.
 *  - Random 256-bit session tokens and share tokens (unguessable, not sequential IDs).
 *  - Share links: expiry timestamp + max-download counter + optional extra password.
 *  - Every download attempt (success or failure) is written to an audit log.
 *  - Uploaded files are stored on disk under a random UUID name, never the user-supplied name.
 */
public class App {

    static final int PORT = 8080;
    static final Path STORAGE_ROOT = Paths.get("storage").toAbsolutePath().normalize();
    static final SecureRandom RNG = new SecureRandom();

    // Master key for AES-GCM, generated fresh at startup (kept in memory only).
    // In the full Spring version this is derived from a persistent configured secret instead.
    static final SecretKey MASTER_KEY = generateAesKey();

    // ---- in-memory "database" ----
    static final Map<String, UserRecord> usersByName = new ConcurrentHashMap<>();
    static final Map<String, String> sessionTokenToUsername = new ConcurrentHashMap<>();
    static final Map<String, SharedFileRecord> filesByShareToken = new ConcurrentHashMap<>();
    static final List<String> auditLog = Collections.synchronizedList(new ArrayList<>());

    public static void main(String[] args) throws IOException {
        Files.createDirectories(STORAGE_ROOT);

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/api/auth/register", App::handleRegister);
        server.createContext("/api/auth/login", App::handleLogin);
        server.createContext("/api/files/upload", App::handleUpload);
        server.createContext("/api/files", App::handleListOrRevoke);
        server.createContext("/api/share/", App::handleShareDownload);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();

        System.out.println("Secure File Sharing System running on http://localhost:" + PORT);
        System.out.println("Storage directory: " + STORAGE_ROOT);
        printCurlExamples();
    }

    // ---------------- Handlers ----------------

    static void handleRegister(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { send(ex, 405, err("Method not allowed")); return; }
        Map<String, String> body = readJsonBody(ex);
        String username = body.get("username");
        String email = body.get("email");
        String password = body.get("password");

        if (isBlank(username) || isBlank(email) || isBlank(password)) {
            send(ex, 400, err("username, email, and password are required")); return;
        }
        if (password.length() < 8) { send(ex, 400, err("Password must be at least 8 characters")); return; }
        if (usersByName.containsKey(username)) { send(ex, 409, err("Username already taken")); return; }

        byte[] salt = randomBytes(16);
        byte[] hash = pbkdf2(password.toCharArray(), salt);
        usersByName.put(username, new UserRecord(username, email, salt, hash));

        String token = issueSession(username);
        send(ex, 200, "{\"token\":\"" + token + "\",\"username\":\"" + username + "\"}");
    }

    static void handleLogin(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { send(ex, 405, err("Method not allowed")); return; }
        Map<String, String> body = readJsonBody(ex);
        String username = body.get("username");
        String password = body.get("password");

        UserRecord user = usersByName.get(username);
        // Deliberately generic error — never reveal whether username or password was wrong.
        if (user == null || !constantTimeEquals(pbkdf2(password == null ? new char[0] : password.toCharArray(), user.salt), user.passwordHash)) {
            send(ex, 401, err("Invalid username or password")); return;
        }
        String token = issueSession(username);
        send(ex, 200, "{\"token\":\"" + token + "\",\"username\":\"" + username + "\"}");
    }

    static void handleUpload(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { send(ex, 405, err("Method not allowed")); return; }
        String username = requireAuth(ex);
        if (username == null) return;

        Map<String, String> query = parseQuery(ex.getRequestURI());
        String filename = query.getOrDefault("filename", "unnamed_file").replaceAll("[/\\\\]", "_");
        int expiryMinutes = parseIntOrDefault(query.get("expiryMinutes"), 60);
        int maxDownloads = parseIntOrDefault(query.get("maxDownloads"), 10);
        String linkPassword = query.get("linkPassword");

        byte[] plaintext = ex.getRequestBody().readAllBytes();
        if (plaintext.length == 0) { send(ex, 400, err("Empty file body")); return; }

        try {
            byte[] iv = randomBytes(12);
            byte[] ciphertext = aesGcmEncrypt(plaintext, MASTER_KEY, iv);
            String storedFilename = UUID.randomUUID().toString();
            Files.write(safeStoragePath(storedFilename), ciphertext);

            String checksum = sha256Hex(plaintext);
            String shareToken = randomUrlSafeToken();
            String linkPasswordHash = isBlank(linkPassword) ? null : sha256Hex(linkPassword.getBytes(StandardCharsets.UTF_8));

            SharedFileRecord record = new SharedFileRecord(
                    shareToken, filename, storedFilename, plaintext.length, checksum,
                    Base64.getEncoder().encodeToString(iv), username, linkPasswordHash,
                    Instant.now(), Instant.now().plusSeconds(expiryMinutes * 60L), maxDownloads);
            filesByShareToken.put(shareToken, record);

            String json = "{\"shareToken\":\"" + shareToken + "\","
                    + "\"shareUrl\":\"/api/share/" + shareToken + "\","
                    + "\"originalFilename\":\"" + jsonEscape(filename) + "\","
                    + "\"fileSizeBytes\":" + plaintext.length + ","
                    + "\"expiresAt\":\"" + record.expiresAt + "\","
                    + "\"maxDownloads\":" + maxDownloads + "}";
            send(ex, 200, json);
        } catch (Exception e) {
            audit("UPLOAD_ERROR", username, ex, false, e.getMessage());
            send(ex, 500, err("Upload failed"));
        }
    }

    static void handleShareDownload(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("GET")) { send(ex, 405, err("Method not allowed")); return; }
        String path = ex.getRequestURI().getPath();
        String shareToken = path.substring(path.lastIndexOf('/') + 1);
        Map<String, String> query = parseQuery(ex.getRequestURI());
        String suppliedPassword = query.get("password");
        String clientIp = ex.getRemoteAddress().getAddress().getHostAddress();

        SharedFileRecord record = filesByShareToken.get(shareToken);
        if (record == null) {
            audit("DOWNLOAD_NOT_FOUND", null, ex, false, "token not found: " + shareToken);
            send(ex, 404, err("File not found or link has expired")); return;
        }
        if (record.revoked) {
            audit("DOWNLOAD_REVOKED", null, ex, false, shareToken);
            send(ex, 404, err("This share link has been revoked")); return;
        }
        if (Instant.now().isAfter(record.expiresAt)) {
            audit("DOWNLOAD_EXPIRED", null, ex, false, shareToken);
            send(ex, 404, err("This share link has expired")); return;
        }
        if (record.downloadCount >= record.maxDownloads) {
            audit("DOWNLOAD_LIMIT", null, ex, false, shareToken);
            send(ex, 410, err("This share link has reached its maximum number of downloads")); return;
        }
        if (record.linkPasswordHash != null) {
            String suppliedHash = suppliedPassword == null ? null : sha256Hex(suppliedPassword.getBytes(StandardCharsets.UTF_8));
            if (!record.linkPasswordHash.equals(suppliedHash)) {
                audit("DOWNLOAD_BAD_PASSWORD", null, ex, false, shareToken);
                send(ex, 403, err("Incorrect or missing link password")); return;
            }
        }

        try {
            byte[] ciphertext = Files.readAllBytes(safeStoragePath(record.storedFilename));
            byte[] iv = Base64.getDecoder().decode(record.iv);
            byte[] plaintext = aesGcmDecrypt(ciphertext, MASTER_KEY, iv);

            record.downloadCount++;
            audit("DOWNLOAD_OK", null, ex, true, shareToken);

            ex.getResponseHeaders().add("Content-Type", "application/octet-stream");
            ex.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"" + record.originalFilename + "\"");
            ex.getResponseHeaders().add("X-File-Checksum-SHA256", record.checksumSha256);
            ex.sendResponseHeaders(200, plaintext.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(plaintext); }
        } catch (Exception e) {
            audit("DOWNLOAD_ERROR", null, ex, false, e.getMessage());
            send(ex, 500, err("Decryption failed — file may be corrupted or tampered with"));
        }
    }

    static void handleListOrRevoke(HttpExchange ex) throws IOException {
        String username = requireAuth(ex);
        if (username == null) return;

        String path = ex.getRequestURI().getPath();
        boolean isRootFilesPath = path.equals("/api/files") || path.equals("/api/files/");

        if (ex.getRequestMethod().equals("GET") && isRootFilesPath) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (SharedFileRecord r : filesByShareToken.values()) {
                if (!r.ownerUsername.equals(username)) continue;
                if (!first) sb.append(",");
                first = false;
                sb.append("{\"shareToken\":\"").append(r.shareToken).append("\",")
                  .append("\"originalFilename\":\"").append(jsonEscape(r.originalFilename)).append("\",")
                  .append("\"fileSizeBytes\":").append(r.fileSizeBytes).append(",")
                  .append("\"downloadCount\":").append(r.downloadCount).append(",")
                  .append("\"maxDownloads\":").append(r.maxDownloads).append(",")
                  .append("\"expiresAt\":\"").append(r.expiresAt).append("\",")
                  .append("\"revoked\":").append(r.revoked).append("}");
            }
            sb.append("]");
            send(ex, 200, sb.toString());
            return;
        }

        if (ex.getRequestMethod().equals("DELETE") && path.startsWith("/api/files/")) {
            String shareToken = path.substring("/api/files/".length());
            SharedFileRecord r = filesByShareToken.get(shareToken);
            if (r == null) { send(ex, 404, err("Not found")); return; }
            if (!r.ownerUsername.equals(username)) { send(ex, 403, err("You do not own this file")); return; }
            r.revoked = true;
            send(ex, 204, "");
            return;
        }

        send(ex, 405, err("Method not allowed"));
    }

    // ---------------- Auth helpers ----------------

    static String issueSession(String username) {
        String token = randomUrlSafeToken();
        sessionTokenToUsername.put(token, username);
        return token;
    }

    /** Returns the authenticated username, or null (and already writes a 401 response) if unauthenticated. */
    static String requireAuth(HttpExchange ex) throws IOException {
        String header = ex.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            send(ex, 401, err("Missing or invalid Authorization header"));
            return null;
        }
        String token = header.substring(7);
        String username = sessionTokenToUsername.get(token);
        if (username == null) {
            send(ex, 401, err("Invalid or expired session token"));
            return null;
        }
        return username;
    }

    // ---------------- Crypto helpers ----------------

    static SecretKey generateAesKey() {
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(256, RNG);
            return gen.generateKey();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static byte[] aesGcmEncrypt(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plaintext);
    }

    static byte[] aesGcmDecrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ciphertext);
    }

    static byte[] pbkdf2(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, 100_000, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static String sha256Hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    static String randomUrlSafeToken() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(32));
    }

    // ---------------- Storage path safety ----------------

    static Path safeStoragePath(String storedFilename) {
        Path resolved = STORAGE_ROOT.resolve(storedFilename).normalize();
        if (!resolved.startsWith(STORAGE_ROOT)) throw new SecurityException("Path traversal attempt blocked");
        return resolved;
    }

    // ---------------- HTTP plumbing (no framework) ----------------

    static void send(HttpExchange ex, int status, String jsonBody) throws IOException {
        byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) { try (OutputStream os = ex.getResponseBody()) { os.write(bytes); } }
        else ex.getResponseBody().close();
    }

    static String err(String message) { return "{\"error\":\"" + jsonEscape(message) + "\"}"; }

    static String jsonEscape(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }

    static boolean isBlank(String s) { return s == null || s.isBlank(); }

    static int parseIntOrDefault(String s, int def) {
        try { return s == null ? def : Integer.parseInt(s); } catch (NumberFormatException e) { return def; }
    }

    static Map<String, String> parseQuery(URI uri) {
        Map<String, String> map = new HashMap<>();
        String query = uri.getRawQuery();
        if (query == null) return map;
        for (String pair : query.split("&")) {
            int idx = pair.indexOf('=');
            if (idx < 0) continue;
            String key = urlDecode(pair.substring(0, idx));
            String val = urlDecode(pair.substring(idx + 1));
            map.put(key, val);
        }
        return map;
    }

    static String urlDecode(String s) {
        try { return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (Exception e) { return s; }
    }

    /** Minimal hand-rolled JSON object parser — supports flat {"key":"value",...} bodies only, which is all this API needs. */
    static Map<String, String> readJsonBody(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> map = new HashMap<>();
        Pattern p = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(body);
        while (m.find()) {
            map.put(m.group(1), m.group(2).replace("\\\"", "\"").replace("\\\\", "\\"));
        }
        return map;
    }

    static void audit(String event, String username, HttpExchange ex, boolean success, String detail) {
        String ip = ex.getRemoteAddress() == null ? "?" : ex.getRemoteAddress().getAddress().getHostAddress();
        auditLog.add(String.format("[%s] %s user=%s ip=%s success=%s detail=%s",
                Instant.now(), event, username, ip, success, detail));
    }

    static void printCurlExamples() {
        System.out.println("""

            --- Try it ---
            # 1. Register
            curl -s -X POST localhost:8080/api/auth/register -H "Content-Type: application/json" \\
              -d '{"username":"alice","email":"alice@example.com","password":"correct-horse-battery"}'

            # 2. Upload a file (use the token from step 1)
            curl -s -X POST "localhost:8080/api/files/upload?filename=notes.txt&expiryMinutes=60&maxDownloads=5" \\
              -H "Authorization: Bearer <token>" --data-binary @notes.txt

            # 3. Download via the share link (no auth needed)
            curl -s -o downloaded.txt "localhost:8080/api/share/<shareToken>"

            # 4. List your files
            curl -s localhost:8080/api/files -H "Authorization: Bearer <token>"
            """);
    }

    // ---------------- Records ----------------

    static class UserRecord {
        final String username, email;
        final byte[] salt, passwordHash;
        UserRecord(String username, String email, byte[] salt, byte[] passwordHash) {
            this.username = username; this.email = email; this.salt = salt; this.passwordHash = passwordHash;
        }
    }

    static class SharedFileRecord {
        final String shareToken, originalFilename, storedFilename, checksumSha256, iv, ownerUsername, linkPasswordHash;
        final long fileSizeBytes;
        final Instant createdAt, expiresAt;
        final int maxDownloads;
        volatile int downloadCount = 0;
        volatile boolean revoked = false;

        SharedFileRecord(String shareToken, String originalFilename, String storedFilename, long fileSizeBytes,
                          String checksumSha256, String iv, String ownerUsername, String linkPasswordHash,
                          Instant createdAt, Instant expiresAt, int maxDownloads) {
            this.shareToken = shareToken; this.originalFilename = originalFilename; this.storedFilename = storedFilename;
            this.fileSizeBytes = fileSizeBytes; this.checksumSha256 = checksumSha256; this.iv = iv;
            this.ownerUsername = ownerUsername; this.linkPasswordHash = linkPasswordHash;
            this.createdAt = createdAt; this.expiresAt = expiresAt; this.maxDownloads = maxDownloads;
        }
    }
}
