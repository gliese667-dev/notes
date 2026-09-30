[Creating certificates](https://github.com/gliese667-dev/notes/blob/main/Creating%20certificates.md) © 2025 by [Ole Martin Håland](https://github.com/gliese667-dev) is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).

-----------------------------------------------------------------------------------------------------------------------
# Creating certificates

This guide uses GitLab as example, but this should work for all TLS connections.

## Table of Contents
- [0) Before you start](#0-before-you-start)
  - [Cryptographic algorithm](#cryptographic-algorithm)
  - [Chain of Trust](#chain-of-trust)
- [1) Create directories](#1-create-directories)
- [2) Create Root CA](#2-create-root-ca)
- [3) Create Intermediate CA](#3-create-intermediate-ca)
- [4) Create leaf(server) cert](#4-create-leafserver-cert)
- [5) Certificate chain for server](#5-certificate-chain-for-server)
- [6) Point server to the cert and reload](#6-point-server-to-the-cert-and-reload)
- [7) Trust on clients (one-time)](#7-trust-on-clients-one-time)
- [Common pitfalls checklist](#common-pitfalls-checklist)
- [Appendix A - Acronyms, keywords, terms](#appendix-a---acronyms-keywords-terms)
  - [Distinguished Name (DN) fields](#distinguished-name-dn-fields)
  - [Extensions & Usage Fields](#extensions--usage-fields)

-----------------------------------------------------------------------------------------------------------------------
### 0) Before you start
#### Cryptographic algorithm

Algorithms used in certificates:
1. RSA (Rivest–Shamir–Adleman)
    - Still the most widely used.
    - Strong, simple, but requires big keys (2048–4096 bits).
    - Slower for signing and handshakes compared to newer algorithms.

2. ECDSA (Elliptic Curve Digital Signature Algorithm)
    - Increasingly popular, especially with Let’s Encrypt, Google, Cloudflare.
    - Much smaller keys (256–384 bits) for the same security.
    - Faster TLS handshakes and lower CPU load than RSA.
    - Security relies on the elliptic curve discrete logarithm problem (ECDLP).

3. EdDSA (Edwards-curve Digital Signature Algorithm: Ed25519 / Ed448)
    - Newer elliptic curve signature scheme (RFC 8032, RFC 8410).
    - Uses **twisted Edwards curves** for efficiency and built-in resistance against common implementation pitfalls.
    - Security relies on the elliptic curve discrete logarithm problem, but with **deterministic signatures** (no per-signature randomness like ECDSA, avoiding nonce-related leaks).
    - Very fast and lightweight — optimized for speed, constant-time implementations, and resistance to side-channel attacks.
    - Supported in OpenSSL 1.1.1+ and modern apps, but still rare in public TLS certificates because browser and CA support is limited.
    - Already popular in SSH, PGP, and some blockchain systems.

They all provide: 
- **Authentication** → proves the cert was issued by the holder of the private key.
- **Integrity** → ensures the data (certificate, message, handshake) hasn’t been tampered with.

The difference is math:
- RSA is based on the difficulty of factoring large numbers.
- ECDSA is based on the difficulty of solving the elliptic curve discrete logarithm problem (ECDLP) — much harder per bit.
- EdDSA is also based on ECDLP, but uses Edwards curves + deterministic signing for stronger safety against bad randomness.

Efficiency:
- ECDSA keys are much shorter for the same security.
- Example:
    - AES-80  ≈ RSA-1024  ≈ ECDSA-160-223
    - AES-112 ≈ RSA-2048  ≈ ECDSA-224-255
    - AES-128 ≈ RSA-3072  ≈ ECDSA-256-383
    - AES-192 ≈ RSA-7680  ≈ ECDSA-384-511
    - AES-256 ≈ RSA-15360 ≈ ECDSA-512

- Performance:
    - RSA: slowest, largest certs.
    - ECDSA: much faster, smaller certs.
    - EdDSA: even faster and more secure against misuse, but limited deployment.

- Adoption:
    - RSA → dominant, universal compatibility.
    - ECDSA → widely deployed by Let’s Encrypt, Google, Apple, Cloudflare, and most modern browsers.
    - EdDSA → supported in OpenSSL, OpenSSH, and modern crypto libraries, but only experimental for TLS certificates.

Practical Recommendations (2025):
- **RSA 2048/3072** → safest default, works everywhere, but larger and slower. Use if you need max compatibility (legacy clients, older browsers, Java apps).
- **ECDSA P-256 / P-384** → preferred modern choice, faster handshakes, smaller certs, widely supported by all modern browsers, servers, and GitLab.
- **EdDSA (Ed25519/Ed448)** → excellent security and performance, but limited TLS support in browsers and CAs. Great for SSH/PGP, experimental for TLS.

#### Chain of Trust
Certificates exist in a [chain of trust](https://en.wikipedia.org/wiki/Chain_of_trust):

| Term              | Chain level  | Meaning |
|:------------------|:-------|:--------|
| Root              | Top    | A self-signed certificate. Usually issued by a trusted [Certificate Authority](Abbr.md) and distributed automatically in system/browser trust stores. Or created by anyone and distributed manually in private PKIs. The receiver must decide if the certificate may be trusted. |
| Intermediate      | Middle | Optional subordinate certificate, usually issued by a trusted [Certificate Authority](Abbr.md) and signed by the root. Not be possible if limited by the root certificate (`pathlen:0`) |
| Intermediate      | Middle | Optional subordinate certificate, linked to previous intermediate certificate in the chain. Eg. issued by your PKI department. May be limited by the root cert `pathlen:1` setting |
| ...               | ...    | Chain may be as long as desired, but may be limited by the root cert (`pathlen`) |
| Leaf / End-Entity | Lower  | The actual certificate for a service or user (e.g., web server [TLS cert](Abbr.md)). |

<br>

![Chain of trust](https://upload.wikimedia.org/wikipedia/commons/8/87/Chain_of_trust_v2.svg)
<p style="font-size: 0.85em; text-align: right;">
  <a href="https://commons.wikimedia.org/wiki/File:Chain_of_trust_v2.svg">Fanyangxi</a>, 
  <a href="https://creativecommons.org/licenses/by-sa/4.0">CC BY-SA 4.0</a>, via Wikimedia Commons
</p>

#### Goal
The goal is to create a self-signed root certificate to sign an intermediate certificate, which in turn will sign the leaf certificate. The leaf certificate will be used as a server certificate in GitLab. The root certificate must be imported into different certificate stores so that clients can verify the certificate chain served by GitLab.

This is the file structure we will create for the [Public Key Infrastructure (PKI)](#appendix-a---acronyms-keywords-terms):
```text
Tree  Permission  Path                               Type            Purpose / Description
----------------------------------------------------------------------------------------------------------------------------------------
┐     drwxr-xr-x  ~/pki                              Directory       Base PKI directory (keys, certs, configs, CSRs).
├─┐   drwxr-xr-x  ~/pki/csr                          Directory       Holds certificate signing requests.
│ ├─  -rw-r--r--  ~/pki/csr/intermediate-ca.csr      CSR             Intermediate CA certificate signing request (signed by Root).
│ └─  -rw-r--r--  ~/pki/csr/leaf.csr                 CSR             Server leaf certificate signing request (signed by Intermediate).
├─┐   drwxr-xr-x  ~/pki/issued                       Directory       Issued certificates and related configs.
│ ├─  -rw-r--r--  ~/pki/issued/intermediate-ca.cnf   OpenSSL config  Config for Intermediate CA CSR & certificate.
│ ├─  -rw-r--r--  ~/pki/issued/intermediate-ca.crt   Certificate     Intermediate CA certificate (signed by Root, 10 years).
│ ├─  -rw-r--r--  ~/pki/issued/intermediate-ca.srl   Serial file     Auto-generated serial file when Intermediate signs certs.
│ ├─  -rw-r--r--  ~/pki/issued/leaf.cnf              OpenSSL config  Config for server leaf certificate CSR (SANs, CA:false, usage).
│ ├─  -rw-r--r--  ~/pki/issued/leaf.crt              Certificate     Leaf(server) certificate (max 825 days).
│ ├─  -rw-r--r--  ~/pki/issued/leaf-cert-ext.cnf     OpenSSL config  Extensions for server leaf certificate (SANs, AKI/SKI).
│ └─  -rw-r--r--  ~/pki/issued/server-chain.crt      Certificate     Canonical server chain file (Server leaf cert + intermediate cert).
├─┐   drwx------  ~/pki/private                      Directory       Holds private keys (restricted access).
│ ├─  -rw-------  ~/pki/private/root-ca.key          Private key     Root CA private key (top authority, kept offline & secure).
│ ├─  -rw-------  ~/pki/private/intermediate-ca.key  Private key     Intermediate CA private key (used to sign leaf certs).
│ └─  -rw-------  ~/pki/private/leaf.key             Private key     Canonical server leaf private key (used by NGINX for TLS).
└─┐   drwxr-xr-x  ~/pki/root                         Directory       Root CA certificate and config.
  ├─  -rw-r--r--  ~/pki/root/root-ca.cnf             OpenSSL config  Config for Root CA (DN fields, CA extensions, usage).
  ├─  -rw-r--r--  ~/pki/root/root-ca.crt             Certificate     Self-signed Root CA certificate (10 years). Trusted on clients.
  └─  -rw-r--r--  ~/pki/root/root-ca.srl             Serial file     Auto-generated serial number file when Root CA signs certs.
```

This is the file structure we will add to GitLab:
```text
Tree  Permission  Path                               Type            Purpose / Description
-----------------------------------------------------------------------------------------------------------------------------------------------
┐     drwxr-xr-x  /etc/gitlab/ssl                    Directory       Base SSL/TLS directory for GitLab.
├─    -rw-------  /etc/gitlab/ssl/gitlab.key         Private key     Runtime copy of GitLab server private key (used by NGINX for TLS).
├─    -rw-r--r--  /etc/gitlab/ssl/gitlab.crt         Certificate     Runtime copy of chain file (GitLab leaf(server) cert + intermediate cert).
```

-----------------------------------------------------------------------------------------------------------------------
### 1) Create directories

==*NOTE! Keep the root key offline if possible (not on the server), generate only the CSR on the server and sign it on a secured machine.*==

```bash
sudo mkdir -p ~/pki/{root,issued,private,csr}

# Owner: rwx, Group: ---, Others: ---
sudo chmod 700 ~/pki/private
cd ~/pki
```

-----------------------------------------------------------------------------------------------------------------------
### 2) Create Root CA 

Create config ``~/pki/root/root-ca.cnf`` (CA:TRUE):
```ini
[ req ]
default_bits       = 4096       # RSA key size if using `req -newkey` (2048 current minimum; 3072 good; 4096 very strong but slower)
default_md         = sha384     # SHA-256 is the standard; SHA-1 is deprecated; SHA-384 pairs well with P-384 (optional)
prompt             = no         # Do not prompt; take DN fields from [ dn ]
distinguished_name = dn         # Use the data provided in [ dn ]
x509_extensions    = v3_ca      # When using `req -x509`, apply CA v3 extensions from [ v3_ca ]

[ dn ]
# None of these are mandated by X.509 itself
countryName            = NO                               # Common
stateOrProvinceName    = Rogaland                         # Sometimes used
localityName           = Sandnes                          # Sometimes used
# streetAddress          =                                  # Rare in CA subjects
organizationName       = Your Company AS                  # Common
organizationalUnitName = Internal PKI                     # Typically a department/team (DigiCert has a url to their webpage)
commonName             = Your Company - Local Root CA     # Common; The CA name shown to users
# givenName              = John Doe                         # Rare in CA subjects
# initials               = JD                               # Rare in CA subjects
# emailAddress           = it-ops@yourcompany.no            # Generally avoid in Subject

[ v3_ca ]
basicConstraints       = critical, CA:true, pathlen:1     # CA with one layer of intermediates allowed (Root -> Intermediate -> Leaf). Set pathlen:0 to not allow intermediate CAs.
keyUsage               = critical, keyCertSign, cRLSign   # Some CAs include digitalSignature, but it's best not to include it unless there’s a specific reason.
subjectKeyIdentifier   = hash
# authorityKeyIdentifier = keyid:always,issuer            # Redundant on Root
# Optional: fill your internal CDP/AIA if you publish them
# crlDistributionPoints  = URI:http://pki.yourcompany.local/crl/root.crl            # Where to fetch revocation lists (CRLs). (Slow, OCSP is faster)
# authorityInfoAccess    = caIssuers;URI:http://pki.yourcompany.local/ca/root.crt   # Download the issuer’s certificate if the client doesn’t have it.
# authorityInfoAccess    = OCSP;URI:http://ocsp.example.com                         # Contact the OCSP responder for real-time revocation status
```

Generate the **Root key** and protect it:
```bash
# Root private key (keep secret!)
# genpkey                                         Generates a private key or key pair.
# -algorithm RSA -pkeyopt rsa_keygen_bits:4096    Alternative 1: Generate RSA type key of 4096 bits (2048 current minimum; 3072 good; 4096 very strong but slower)
# -algorithm EC -pkeyopt ec_paramgen_curve:P-256  Alternative 2: Generate EC type key P-256 (P-256 (prime256v1) — fast, widely compatible; 
#                                                                or P-384 (secp384r1) — slightly stronger; pair with sha384 if you like
# [-aes-256-cbc]                                  Optional: Encrypts the private key using the specified algorithm
#                                                           aes-256-cbc - Ubiquitous, strong, supported everywhere
#                                                           aes-128-cbc - Faster; 128-bit is already very strong
# -out ~/pki/private/root-ca.key                  Output the private key to the specified file.

sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -aes-256-cbc -out ~/pki/private/root-ca.key

# Owner: rw-, Group: ---, Others: ---
sudo chmod 600 ~/pki/private/root-ca.key
```

You may review it like this:
```bash
# Private and public key
sudo openssl pkey -in ~/pki/private/root-ca.key -text -noout
```

Generate the **Root certificate** (10 years):
```bash
# Self-signed Root CA cert (10 years validity)
sudo openssl req -x509 -new -days 3650 \
  -key ~/pki/private/root-ca.key \
  -out  ~/pki/root/root-ca.crt \
  -config ~/pki/root/root-ca.cnf
```

You may review it like this:
```bash
openssl x509 -in ~/pki/root/root-ca.crt -text -noout
```

**Distribute and trust this on clients:** 
``~/pki/root/root-ca.crt``

Download from Linux machine to Windows machine with Command Prompt(cmd) or PowerShell:
`scp user@linux-server:~/pki/root/root-ca.crt C:\Users\YourName\Downloads\`

[More about this in chapter 7](#7-trust-on-clients-one-time)

-----------------------------------------------------------------------------------------------------------------------
### 3) Create Intermediate CA

Create config `~/pki/issued/intermediate-ca.cnf` (CA:TRUE, issued by Root):
```ini
[ req ]
default_bits       = 2048               # RSA key size if using `req -newkey` (2048 current minimum; 3072 good; 4096 very strong but slower)
default_md         = sha256             # SHA-256 is the standard; SHA-1 is deprecated; SHA-384 pairs well with P-384 (optional)
prompt             = no                 # Do not prompt; take DN fields from [ dn ]
distinguished_name = dn                 # Use the data provided in [ dn ]

[ dn ]
# None of these are mandated by X.509 itself
countryName            = NO                               # Common
stateOrProvinceName    = Rogaland                         # Sometimes used
localityName           = Sandnes                          # Sometimes used
# streetAddress          =                                  # Rare in CA subjects
organizationName       = Your Company AS                  # Common
organizationalUnitName = Internal PKI                     # Typically a department/team (DigiCert has a url to their webpage)
commonName             = Your Company - Intermediate CA   # Name of this Intermediate CA
# givenName              = John Doe                         # Rare in CA subjects
# initials               = JD                               # Rare in CA subjects
# emailAddress           = it-ops@yourcompany.no            # Generally avoid in Subject


[ v3_intermediate_ca  ]
basicConstraints       = critical, CA:true                # Intermediate CA
keyUsage               = critical, keyCertSign, cRLSign   # Least privilege for a CA, can add digitalSignature
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
extendedKeyUsage       = serverAuth, clientAuth

# Recommended to publish these for chain-building and revocation (uncomment and set your URLs):
# crlDistributionPoints = URI:http://pki.yourcompany.local/crl/intermediate.crl
# authorityInfoAccess   = caIssuers;URI:http://pki.yourcompany.local/ca/intermediate.crt
# authorityInfoAccess   = OCSP;URI:http://ocsp.yourcompany.local

# Optional: name constraints (advanced; use with care)
# NOTE: Not widely supported; can break clients if misconfigured.
# nameConstraints       = permitted;DNS:.yourcompany.local      # Any leaf cert issued by that intermediate must end in .yourcompany.com.
# nameConstraints       = permitted;IP:10.0.0.0/8               # Certificates must be in the 10.x.x.x range.
# nameConstraints       = excluded;DNS:.evil.com                # Prevents issuance for *.evil.com.
```
Generate the **Intermediate key**:
```bash
# Intermediate private key (keep secret!)
# genpkey                                         Generates a private key or key pair.
# -algorithm RSA -pkeyopt rsa_keygen_bits:4096    Alternative 1: Generate RSA type key of 4096 bits (2048 current minimum; 3072 good; 4096 very strong but slower)
# -algorithm EC -pkeyopt ec_paramgen_curve:P-256  Alternative 2: Generate EC type key P-256 (P-256 (prime256v1) — fast, widely compatible; 
#                                                                or P-384 (secp384r1) — slightly stronger; pair with sha384 if you like
# [-aes-256-cbc]                                  Optional: Encrypts the private key using the specified algorithm
#                                                           aes-256-cbc - Ubiquitous, strong, supported everywhere
#                                                           aes-128-cbc - Faster; 128-bit is already very strong
# -out ~/pki/private/root-ca.key                  Output the private key to the specified file.

sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-128-cbc -out ~/pki/private/intermediate-ca.key

# Owner: rw-, Group: ---, Others: ---
sudo chmod 600 ~/pki/private/intermediate-ca.key
```

*Note: Using `-aes-128-cbc` encrypts the Intermediate CA private key. This is ideal if the key is stored offline and used only for occasional signing.  
If your Intermediate CA is kept online (e.g., automated issuance), consider generating it **without encryption** so services can access it without manual passphrase entry.*


You may review it like this:
```bash
# Private and public key
sudo openssl pkey -in ~/pki/private/intermediate-ca.key -text -noout
```

Generate the **Intermediate [CSR](#appendix-a---acronyms-keywords-terms)**:
```bash
sudo openssl req -new -sha256 \
  -key ~/pki/private/intermediate-ca.key \
  -out ~/pki/csr/intermediate-ca.csr \
  -config ~/pki/issued/intermediate-ca.cnf
```

You may review it like this:
```bash
openssl req -in ~/pki/csr/intermediate-ca.csr -text -noout
```

Sign the intermediate with the **Root CA** (10 years):
```bash
sudo openssl x509 -req -days 3650 \
  -in  ~/pki/csr/intermediate-ca.csr \
  -CA  ~/pki/root/root-ca.crt \
  -CAkey ~/pki/private/root-ca.key \
  -CAcreateserial \
  -out ~/pki/issued/intermediate-ca.crt \
  -extensions v3_intermediate_ca \
  -extfile ~/pki/issued/intermediate-ca.cnf
```

You may review it like this:
```bash
openssl x509 -in ~/pki/issued/intermediate-ca.crt -text -noout
```

In some cases it could be necessary to distribute this intermediate certificate alongside the root:
- Root goes into **Trusted Root Certification Authorities**.
- Intermediate goes into **Intermediate Certification Authorities**.

-----------------------------------------------------------------------------------------------------------------------
### 4) Create leaf(server) cert 

Create config ``~/pki/issued/leaf.cnf`` (CA:FALSE, SANs, EKUs):
```ini
[ req ]
default_bits       = 2048               # RSA key size if using `req -newkey` (2048 current minimum; 3072 good; 4096 very strong but slower)
default_md         = sha256             # SHA-256 is the standard; SHA-1 is deprecated; SHA-384 pairs well with P-384 (optional)
prompt             = no                 # Do not prompt; take DN fields from [ dn ]
distinguished_name = dn                 # Use the data provided in [ dn ]
req_extensions     = req_ext            # Extensions to embed in the CSR (SAN, KU/EKU hints)

[ dn ]
# None of these are mandated by X.509 itself
countryName            = NO                                 # Common
stateOrProvinceName    = Rogaland                           # Sometimes used
localityName           = Sandnes                            # Sometimes used
# streetAddress          =                                    # Rare in CA subjects
organizationName       = Your Company AS                    # Common
organizationalUnitName = Internal PKI                       # Typically a department/team (DigiCert has a url to their webpage)
commonName             = Your Company - Server Name         # CN is informational; SANs are what clients validate
# givenName              = John Doe                           # Rare in CA subjects
# initials               = JD                                 # Rare in CA subjects
# emailAddress           = it-ops@yourcompany.no              # Generally avoid in

# Recommended to publish these for chain-building and revocation (uncomment and set your URLs):
# crlDistributionPoints = URI:http://pki.yourcompany.local/crl/intermediate.crl
# authorityInfoAccess   = caIssuers;URI:http://pki.yourcompany.local/ca/intermediate.crt
# authorityInfoAccess   = OCSP;URI:http://ocsp.yourcompany.local

[ req_ext ]
# These go into the CSR. The final cert’s extensions are set at signing time by the CA.
basicConstraints = critical, CA:false                               # Leaf certificate

# For RSA leaf(server) certs, keeping both is common practice:
# - digitalSignature is required for ECDHE handshake auth.
# - keyEncipherment is kept for legacy RSA key exchange (or just convention).
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth                                       # TLS server certificate

# For ECDSA leaf(server) certs:
# keyUsage = critical, digitalSignature
# extendedKeyUsage = serverAuth

subjectAltName   = @alt_names                                       # Hostnames/IPs the cert should be valid for provided in [ alt_names ]

[ alt_names ]
DNS.1 = hostname
DNS.2 = hostname.yourcompany.local
DNS.3 = hostname.yourcompany.no
# DNS.4 = *.hostname.yourcompany.no      # (optional wildcard)
# IP.1  = 10.0.0.15                      # (optional IP SAN)
# Add more DNS.N lines if you have more hostnames
```

Generate **Leaf key**:

```bash
# Leaf private key (keep secret!)
# genpkey                                         Generates a private key or key pair.
# -algorithm RSA -pkeyopt rsa_keygen_bits:4096    Alternative 1: Generate RSA type key of 4096 bits (2048 current minimum; 3072 good; 4096 very strong but slower)
# -algorithm EC -pkeyopt ec_paramgen_curve:P-256  Alternative 2: Generate EC type key P-256 (P-256 (prime256v1) — fast, widely compatible; 
#                                                                or P-384 (secp384r1) — slightly stronger; pair with sha384 if you like
# [-aes-256-cbc]                                  Optional: Encrypts the private key using the specified algorithm
#                                                           aes-256-cbc - Ubiquitous, strong, supported everywhere
#                                                           aes-128-cbc - Faster; 128-bit is already very strong
#                                                           NOTE: Encrypting is not recommended for leaf key as servers may not be able to prompt for a password at runtime.
# -out ~/pki/private/root-ca.key                  Output the private key to the specified file.

sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ~/pki/private/leaf.key

# Owner: rw-, Group: ---, Others: ---
sudo chmod 600 ~/pki/private/leaf.key
```

You may review it like this:
```bash
# Private and public key
sudo openssl pkey -in ~/pki/private/leaf.key -text -noout
```

Generate **Leaf CSR**:
```bash
# CSR
sudo openssl req -new \
  -key ~/pki/private/leaf.key \
  -out ~/pki/csr/leaf.csr \
  -config ~/pki/issued/leaf.cnf
```

You may review it like this:
```bash
openssl req -in ~/pki/csr/leaf.csr -text -noout
```

Signing-time extensions (add AKI/SKI here)

Create ``~/pki/issued/leaf-cert-ext.cnf``:
```ini
[ server_cert ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature, keyEncipherment    # RSA; for ECDSA use only digitalSignature
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names
authorityKeyIdentifier = keyid,issuer
subjectKeyIdentifier   = hash

[ alt_names ]
DNS.1 = hostname
DNS.2 = hostname.yourcompany.local
DNS.3 = hostname.yourcompany.no
```

Sign the CSR with the **Intermediate CA**:
```bash
# CA/Browser Forum Baseline Requirements (which all major browsers follow) limit TLS server certificates to a maximum of 825 days (~27 months).
sudo openssl x509 -req -days 825 \
  -in  ~/pki/csr/leaf.csr \
  -CA  ~/pki/issued/intermediate-ca.crt \
  -CAkey ~/pki/private/intermediate-ca.key \
  -CAcreateserial \
  -out ~/pki/issued/leaf.crt \
  -extfile ~/pki/issued/leaf-cert-ext.cnf \
  -extensions server_cert

# Owner: rw-, Group: r--, Others: r--
sudo chmod 644 ~/pki/issued/leaf.crt
```

You may review it like this:
```bash
openssl x509 -in ~/pki/issued/leaf.crt -text -noout

# Confirm the cert’s public key matches the private key
openssl x509 -in ~/pki/issued/leaf.crt -noout -pubkey | openssl sha256
sudo openssl pkey -in ~/pki/private/leaf.key -pubout | openssl sha256
# The two digests must be identical
```

-----------------------------------------------------------------------------------------------------------------------
### 5) Certificate chain for server

Concatenate leaf cert + intermediate cert into a server chain file:
```bash
sudo cat ~/pki/issued/leaf.crt ~/pki/issued/intermediate-ca.crt | sudo tee ~/pki/issued/server-chain.crt
```

*NOTE: Order matters: leaf cert first, intermediate second. Some TLS stacks fail if reversed.*

Verify it like this:
```bash
openssl crl2pkcs7 -nocrl -certfile ~/pki/issued/server-chain.crt | openssl pkcs7 -print_certs -noout
```

Test against root:
```bash
openssl verify -verbose \
  -CAfile ~/pki/root/root-ca.crt \
  -untrusted ~/pki/issued/intermediate-ca.crt \
  ~/pki/issued/leaf.crt

# Verify chain + hostname (OpenSSL 1.1.0+)
openssl verify -CAfile ~/pki/root/root-ca.crt \
  -untrusted ~/pki/issued/intermediate-ca.crt \
  -verify_hostname gitlab \
  ~/pki/issued/leaf.crt
```

-----------------------------------------------------------------------------------------------------------------------
### 6) Point server to the cert and reload

Example with [Setting up GitLab with certificates for TLS](GitLab.md#setting-up-gitlab-with-certificates-for-tls)

-----------------------------------------------------------------------------------------------------------------------
### 7) Trust on clients (one-time)
**Windows (PowerShell, run as Administrator):**
```powershell
# Add the Root CA by its path and name:
Import-Certificate -FilePath "C:\Path\to\root-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root

# To remove it again: Remove the Root CA by its subject name:
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*Your Company - Local Root CA*" } | Remove-Item
```

**Debian/Ubuntu:**
Copy the root certificate to `/usr/local/share/ca-certificates/`
```bash 
update-ca-certificates

# To remove the Root CA file and refresh trust store
sudo rm /usr/local/share/ca-certificates/root-ca.crt
sudo update-ca-certificates --fresh
```

**RHEL/CentOS/Fedora:**
Copy the root certificate to `/etc/pki/ca-trust/source/anchors/`
```bash
sudo update-ca-trust extract

# To remove the Root CA file and refresh trust store
sudo rm /etc/pki/ca-trust/source/anchors/root-ca.crt
sudo update-ca-trust extract
```

**Arch Linux:**
Copy the root certificate to `/etc/pki/ca-trust/source/anchors/`
```bash
trust anchor root-ca.crt

# To remove the Root CA from the trust store
sudo trust anchor --remove root-ca.crt

# Or find it by name and remove explicitly:
trust list | grep "Your Company - Local Root CA"

```

**Firefox:**
Either enable system cert store:
``about:config`` → ``security.enterprise_roots.enabled = true`` → restart

Or import and trust this specific CA:
Settings → Privacy & Security → Certificates → View Certificates → **Authorities** → **Import** ``root-ca.crt`` → check “Trust this CA to identify websites.”

To remove the Root CA from Firefox:
Go to Settings → Privacy & Security → Certificates → View Certificates → **Authorities**
Select the imported Root CA (e.g. Your Company – Local Root CA)
Click Delete or Distrust


You do **not** import the leaf(server) cert anywhere if the Root is trusted.

-----------------------------------------------------------------------------------------------------------------------
### Common pitfalls checklist

- [ ] Browsing to a different hostname than the SANs (e.g., DNS suffix makes ``gitlab`` resolve to ``gitlab.corp.local``). Add every used name to SANs.
- [ ] Old certs cached by GitLab: after replacing files, run ``gitlab-ctl reconfigure`` and ``gitlab-ctl hup nginx``.
- [ ] Accidentally making the leaf(server) cert ``CA:TRUE`` → Firefox error ``MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY``. The config above sets ``CA:FALSE``.
- [ ] Wrong file permissions (too open or too restrictive) can cause NGINX to fail loading the cert/key.

-----------------------------------------------------------------------------------------------------------------------
### Appendix A - Acronyms, keywords, terms

| Term              | Meaning | Short explanation |
|-------------------|---------|--------------|
| AES               | [Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)| A symmetric cipher (used for bulk data encryption, not certificates). |
| CA                | [Certificate authority](https://en.wikipedia.org/wiki/Certificate_authority) | Entity that stores, signs, and issues digital certificates. |
| CRL               | [Certificate revocation list](https://en.wikipedia.org/wiki/Certificate_revocation_list) | List of digital certificates that have been revoked by the issuing certificate authority (CA) before their scheduled expiration date and should no longer be trusted". |
| DER               | [DER encoding](https://en.wikipedia.org/wiki/X.690#DER_encoding) | The parent format of PEM. It's useful to think of it as a binary version of the base64-encoded PEM file. Not routinely used very much outside of Windows. |
| DSA               | [Digital Signature Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) | Public-key cryptosystem and Federal Information Processing Standard for digital signatures, based on the mathematical concept of modular exponentiation and the discrete logarithm problem. |
| ECDSA             | [Elliptic Curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) | Offers a variant of the Digital Signature Algorithm (DSA) which uses elliptic-curve cryptography.  |
| EdDSA             | [Edwards-curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/EdDSA) | Digital signature scheme using a variant of Schnorr signature based on twisted Edwards curves. It is designed to be faster than existing digital signature schemes without sacrificing security. |
| FQDN              | [Fully Qualified Domain Name](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) | A domain name that specifies its exact location in the tree hierarchy of the Domain Name System (DNS) eg. `hostname.domain.local` |
| NGINX             | [nginx](https://en.wikipedia.org/wiki/Nginx) | High-performance HTTP/TLS reverse proxy bundled with GitLab. |
| OCSP              | [Online Certificate Status Protocol](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) | Internet protocol used for obtaining the revocation status of an X.509 digital certificate. It was created as an alternative to certificate revocation lists (CRL), specifically addressing certain problems associated with using CRLs in a public key infrastructure (PKI) |
| OpenSSL           | [OpenSSL](https://en.wikipedia.org/wiki/OpenSSL) | Comprehensive, open-source cryptography toolkit that implements SSL and TLS. It provides a library of cryptographic functions and a command-line utility for managing private keys, certificates, and performing various cryptographic operations such as encryption, decryption, and hash calculations. 
| PEM               | [Privacy-Enhanced Mail](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) | De facto file format for storing and sending cryptographic keys, certificates, and other data. Used preferentially by open-source software because it is text-based and therefore less prone to translation/transmission errors. It can have a variety of extensions (.pem, .key, .cer, .cert, more) |
| PKCS7 / CMS       | [Public Key Cryptography Standards](https://en.wikipedia.org/wiki/PKCS) | [#7](https://en.wikipedia.org/wiki/PKCS_7) - An open standard used by Java and supported by Windows. Does not contain private key material. |
| PKCS10 / CSR      | [Certificate Signing Request](https://en.wikipedia.org/wiki/Certificate_signing_request) | [#10](https://en.wikipedia.org/wiki/PKCS_10) - A message sent from an applicant to a certificate authority in order to apply for a digital identity certificate. |
| PKCS12            | [Public Key Cryptography Standards](https://en.wikipedia.org/wiki/PKCS) | [#12](https://en.wikipedia.org/wiki/PKCS_12) - A Microsoft private standard (PFX) that was later defined in an RFC that provides enhanced security versus the plain-text PEM format. This can contain private key and certificate chain material. Its used preferentially by Windows systems, and can be freely converted to PEM format through use of openssl. |
| PKI               | [Public Key Infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure) | Set of roles, policies, hardware, software and procedures needed to create, manage, distribute, use, store and revoke digital certificates and manage public-key encryption.  |
| RSA               | [Rivest–Shamir–Adleman](https://en.wikipedia.org/wiki/RSA_cryptosystem) | Family of public-key cryptosystems, one of the oldest widely used for secure data transmission. |
| SSL               | [Secure Sockets Layer](https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0,_2.0,_and_3.0) | Outdated internet security protocol |
| TLS               | [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security) | A cryptographic protocol designed to provide communications security over a computer network, such as the Internet. |

General [Abbreviations](Abbr.md)

##### File types
| Extension | Explanation |
|-----------|--------------|
| .cert .cer .crt | A .pem (or rarely .der) formatted file with a different extension, one that is recognized by Windows Explorer as a certificate, which .pem is not. |
| .crl        | A certificate revocation list. Certificate Authorities produce these as a way to de-authorize certificates before expiration. You can sometimes download them from CA websites. |
| .csr      | This is a Certificate Signing Request. Some applications can generate these for submission to certificate-authorities. The actual format is PKCS10 which is defined in RFC 2986. It includes some/all of the key details of the requested certificate such as subject, organization, state, whatnot, as well as the public key of the certificate to get signed. These get signed by the CA and a certificate is returned. The returned certificate is the public certificate (which includes the public key but not the private key), which itself can be in a couple of formats. |
| .der       | A way to encode ASN.1 syntax in binary, a .pem file is just a Base64 encoded .der file. OpenSSL can convert these to .pem (openssl x509 -inform der -in to-convert.der -out converted.pem). Windows sees these as Certificate files. By default, Windows will export certificates as .DER formatted files with a different extension. Like... |
| .key      | This is a (usually) PEM formatted file containing just the private-key of a specific certificate and is merely a conventional name and not a standardized one. In Apache installs, this frequently resides in /etc/ssl/private. The rights on these files are very important, and some programs will refuse to load these certificates if they are set wrong. |
| .pem      | Defined in RFC 1422 (part of a series from 1421 through 1424) this is a container format that may include just the public certificate (such as with Apache installs, and CA certificate files /etc/ssl/certs), or may include an entire certificate chain including public key, private key, and root certificates. Confusingly, it may also encode a CSR (e.g. as used here) as the PKCS10 format can be translated into PEM. The name is from Privacy Enhanced Mail (PEM), a failed method for secure email but the container format it used lives on, and is a base64 translation of the x509 ASN.1 keys. |
| .pkcs12 .pfx .p12 | Originally defined by RSA in the Public-Key Cryptography Standards (abbreviated PKCS), the "12" variant was originally enhanced by Microsoft, and later submitted as RFC 7292. This is a password-protected container format that contains both public and private certificate pairs. Unlike .pem files, this container is fully encrypted. Openssl can turn this into a .pem file with both public and private keys: openssl pkcs12 -in file-to-convert.p12 -out converted-file.pem -nodes |
| .p7b | Defined in RFC 2315 as PKCS number 7 (PKCS#7 / CMS), a format used by Windows for certificate interchange. Contains certificates (and optionally CRLs) but no private key material. Unlike .pem style certificates, this format has a defined way to include certification-path certificates. |
| .keystore | Not PKCS#7 — historically Java's own JKS (Java KeyStore) format; modern Java (9+) defaults to a PKCS12-based keystore that also uses this extension. Unlike `.p7b`, a keystore can hold private keys alongside certificates. |

##### Distinguished Name (DN) fields
| Abbreviation | Long name                | Meaning |
|--------------|--------------------------|---------|
| C            | `countryName`            | Two-letter ISO 3166 country code (e.g., `NO` for Norway). |
| ST           | `stateOrProvinceName`    | Full state/province/region name (e.g., `Oslo`, `California`). |
| L            | `localityName`           | City or locality (e.g., `Oslo`). |
| O            | `organizationName`       | Legal entity/organization (e.g., `Your Company AS`). |
| OU           | `organizationalUnitName` | Department/unit inside the organization (e.g., `IT Operations`). |
| CN           | `commonName`             | Entity name: descriptive for a CA, hostname for a server (now replaced by SANs). |
| emailAddress | `emailAddress`           | Contact email (optional, less common in modern certs). |

##### Extensions & Usage Fields
| Abbreviation | Keyword                  | Meaning |
|--------------|--------------------------|---------|
|              | `CA:true` / `CA:false`   | Marks whether the cert may act as a Certificate Authority. |
|              | `pathlen`                | Max number of subordinate CA levels allowed below this CA (does not restrict end-entities). |
| KU           | `keyUsage`               | Specifies key purposes: `digitalSignature`, `keyEncipherment`, `keyCertSign`, `cRLSign`, etc. |
| EKU          | `extendedKeyUsage`       | Narrower purposes like `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`. |
| SAN          | `subjectAltName`         | Alternative identities: DNS names, IPs, URIs, emails. Required for TLS hostnames. |
| SKI          | `subjectKeyIdentifier`   | Unique identifier derived from the cert’s public key. |
| AKI          | `authorityKeyIdentifier` | Links cert to its issuer (usually matches the issuer’s SKI). |

-----------------------------------------------------------------------------------------------------------------------
[Creating certificates](https://github.com/gliese667-dev/notes/blob/main/Creating%20certificates.md) © 2025 by [Ole Martin Håland](https://github.com/gliese667-dev) is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
