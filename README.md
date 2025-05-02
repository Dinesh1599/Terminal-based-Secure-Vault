<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  

<h1>🔐 Secure Vault</h1>
<p>A terminal-based encrypted data storage application built in Python. Secure Vault allows users to store sensitive data such as passwords or notes in an encrypted SQLite database using AES-256 encryption and PBKDF2 key derivation. It also includes auto-locking on inactivity to protect sessions.</p>

<hr>

<h2>🚀 Features</h2>
<ul>
  <li>✅ User Signup & Login with secure password hashing (<code>bcrypt</code>)</li>
  <li>🔐 AES-256 encryption (CFB mode) for all vault entries</li>
  <li>🧠 PBKDF2-HMAC-SHA256 for secure key derivation</li>
  <li>🗂 Add and view encrypted data entries</li>
  <li>🔒 Auto-locks after inactivity (default: 2 minutes)</li>
  <li>🔁 Re-authentication required to unlock</li>
  <li>❌ Protects against brute-force and rainbow table attacks</li>
</ul>

<hr>

<h2>🧠 How It Works</h2>
<ol>
  <li><strong>User signs up</strong> with a username + master password.</li>
  <li><strong>Password is hashed</strong> (bcrypt) and stored with a unique salt.</li>
  <li><strong>Encryption key</strong> is derived from the password using PBKDF2.</li>
  <li><strong>All secrets</strong> are encrypted using AES-256 before storage.</li>
  <li>If inactive, the vault <strong>auto-locks</strong> and requires re-authentication.</li>
</ol>

<hr>

<h2>🏗️ Project Structure</h2>
<pre><code>secure_vault/
├── vault.py           # Main app (UI & logic)
├── auth.py            # Signup and login logic
├── database.py        # SQLite schema and data handling
├── crypto_utils.py    # Key derivation, encryption, decryption
├── requirements.txt   # Dependencies
└── vault.db           # Auto-created encrypted local database
</code></pre>

<hr>

<h2>💪 Requirements</h2>
<ul>
  <li>Python 3.8+</li>
  <li>Install packages with:</li>
</ul>
<pre><code>pip install -r requirements.txt</code></pre>

<hr>

<h2>🖥️ Usage</h2>
<pre><code>python vault.py</code></pre>
<p>You'll be prompted to:</p>
<ul>
  <li>Sign up or log in</li>
  <li>Add or view secure entries</li>
  <li>Auto-logout will occur if idle for 2+ minutes</li>
</ul>

<hr>

<h2>🔐 Security Highlights</h2>
<ul>
  <li>AES-256 encryption in CFB mode</li>
  <li>Salted & hashed passwords (bcrypt)</li>
  <li>PBKDF2 key derivation (100,000 iterations)</li>
  <li>Auto-lock on inactivity</li>
  <li>Three strike re-authentication limit before exit</li>
</ul>

<hr>

<h2>📈 Future Enhancements</h2>
<ul>
  <li>🔐 Two-Factor Authentication (2FA)</li>
  <li>📤 Encrypted backup/restore</li>
  <li>🧪 Automated tests</li>
  <li>📁 File encryption support</li>
</ul>

</body>
</html>
