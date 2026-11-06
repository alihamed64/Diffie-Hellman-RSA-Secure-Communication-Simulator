# Diffie-Hellman-RSA-Secure-Communication-Simulator
Implementation of RSA (key generation, Miller-Rabin primality testing, SHA-256 signatures) and Diffie-Hellman key exchange from scratch in Python; includes mutual signature authentication to prevent man-in-the-middle attacks and AES-256-CBC to encrypt and sign a transaction file end to end. 

Code was generated with AI; I performed a manual code security audit and utilized automated tools like Bandit and pip-audit to fix various vulnerabilities that was found in the generated code.

<h1>Findings and Fixes:</h1>

* Deprecated pycrypto library (High, Bandit B413): The AI used an abandoned library with known vulnerabilities. Migrated to pycryptodome.
* Assert used for security checks (Low, Bandit B101): Assertions get stripped in optimized Python, meaning critical checks would silently disappear. Replaced with if/raise statements.
* Textbook RSA (Critical, manual): The AI implemented RSA without padding, which is vulnerable to forgery. Replaced with RSA-PSS
* Weak KDF (Medium, manual): The shared secret was hashed once with SHA-256, which lacks context binding. Replaced with HKDF
* AES-CBC (Medium, manual): CBC is malleable, meaning an attacker can manipulate the plaintext without detection. Replaced with AES-GCM, which provides authenticated encryption
* Missing DH public value validation (Medium, manual): No range check on the peer's public value, allowing small subgroup attacks. Added validation
 
