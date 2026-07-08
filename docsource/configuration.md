## Overview
The **Keyfactor ACME CA Gateway Plugin** enables certificate enrollment using the [ACME protocol (RFC 8555)](https://datatracker.ietf.org/doc/html/rfc8555), providing automated certificate issuance via any compliant Certificate Authority. This plugin is designed for **enrollment-only workflows** — it **does not support synchronization or revocation** of certificates.

### 🔧 What It Does
This plugin allows Keyfactor Gateways to:
- Submit CSRs to ACME-based CAs.
- Complete domain validation via DNS-01 challenges.
- Automatically retrieve and return signed certificates.

Once a certificate is issued, the plugin returns the PEM-encoded certificate to the Gateway.

### ✅ ACME Providers Tested
This plugin has been tested and confirmed to work with the following ACME providers:
- **Let's Encrypt**
- **Google ACME (Certificate Authority Service)**
- **ZeroSSL** (functional but known slowness may cause timeouts)
- **Buypass**

It is designed to be provider-agnostic and should work with any standards-compliant ACME server.

### 🌐 DNS Providers (Pluggable)
DNS-01 challenge automation is handled by **separate, pluggable DNS provider plugins** that are deployed alongside the AnyCA Gateway — they are no longer built into this plugin. The Gateway resolves the appropriate DNS provider plugin per domain at enrollment time.

For the current list of available DNS provider plugins, see the Keyfactor GitHub organization:

👉 **[Keyfactor DNS provider plugins (`-dnsplugin`)](https://github.com/orgs/Keyfactor/repositories?q=-dnsplugin)**

Each plugin repository documents its own supported authentication methods and configuration keys. New DNS providers can be added by publishing a new plugin that implements the Gateway's `IDomainValidator` interface — no change to this ACME plugin is required.

---

### 🔁 Enrollment Flow Summary

```text
1. Keyfactor Gateway submits CSR and SAN metadata to plugin.
2. Plugin initializes ACME client and creates a new order.
3. For each domain:
   a. Retrieve DNS-01 challenge.
   b. Resolve any CNAME delegation: follow the CNAME chain from `_acme-challenge.<domain>` to its terminal target (see CNAME Delegation below).
   c. Select the DNS provider plugin for the zone that owns the (resolved) record name and publish the challenge TXT record there.
   d. Wait for DNS propagation and validate record.
   e. Notify ACME provider to trigger validation.
4. Once all challenges are valid, finalize the order using CSR.
5. Download the signed certificate from ACME provider.
6. Return PEM certificate to the Gateway.
```

The plugin uses a modular design that separates ACME communication logic and DNS challenge automation, allowing for future extensibility in both areas.

> ⚠️ Revocation, certificate synchronization, and renewal tracking are intentionally **not implemented** in this plugin. All lifecycle tracking must be handled externally (e.g., via Keyfactor monitoring or Gateway automation).

## Compatibility

The Acme AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.


## Requirements

### DNS Providers

This plugin automates DNS-01 challenges using pluggable DNS provider implementations. These providers create and remove TXT records to prove domain control to ACME servers.

<details>
<summary><strong>🔌 Available DNS Provider Plugins</strong></summary>

DNS providers are distributed as **standalone plugins**, each in its own repository, and are deployed alongside the AnyCA Gateway rather than bundled into this ACME plugin. This lets you add or upgrade a DNS provider without rebuilding the ACME plugin.

For the current, authoritative list of available DNS provider plugins, query the Keyfactor GitHub organization:

👉 **[github.com/orgs/Keyfactor/repositories?q=-dnsplugin](https://github.com/orgs/Keyfactor/repositories?q=-dnsplugin)**

Each plugin's own repository is the source of truth for its supported authentication methods, required configuration keys, and setup instructions. Configure the DNS provider(s) through the AnyCA Gateway's **Domain Validation** configuration; the Gateway resolves the correct plugin per domain at enrollment time.

</details>

<details>
<summary><strong>⏱ DNS Propagation Logic</strong></summary>

Before submitting ACME challenges, the plugin verifies DNS propagation using multiple public resolvers (Google, Cloudflare, OpenDNS, Quad9). A record must be visible on **at least 3 servers** to proceed, with up to **3 retries** spaced by 10 seconds.

This logic is handled by the `DnsVerificationHelper` class and ensures a high-confidence validation before proceeding.

</details>

<details>
<summary><strong>🔗 CNAME Delegation (Proxy) Lookup</strong></summary>

Many organizations do not want ACME automation to hold write access to their production DNS zone. The industry-standard pattern is to **delegate just the ACME challenge name** to a separate, isolated validation zone using a `CNAME` record. The plugin supports this transparently.

#### Why delegate?

A `CNAME` at `_acme-challenge.<domain>` points challenge validation at another zone. ACME automation then only needs write access to that isolated zone — never the production zone. A `CNAME` also cannot coexist with any other record type at the same name (RFC 1034), so the TXT record **must** be created at the CNAME's target, not at the original challenge name.

#### How the plugin resolves it

Before publishing the challenge record, the plugin runs the `CnameResolver`, which:

1. Issues a DNS `CNAME` query for `_acme-challenge.<domain>`.
2. **Follows the chain to its terminus.** Delegation can be nested multiple levels deep (`A → B → C → …`); the resolver re-queries at each hop and stops only when it reaches a name that has no further `CNAME`. That terminal name is where the TXT record is created.
3. Returns the original name unchanged when **no** `CNAME` exists — so non-delegated domains behave exactly as before (fully backwards compatible).

Safety guards: the resolver detects loops (a name that reappears in the chain) and enforces a maximum depth of **10 hops**, logging a warning and stopping at the last good name rather than looping forever.

#### Provider selection follows the delegation

The DNS provider plugin is resolved against the **name where the record actually lands**:

- **No delegation** → the provider is selected for the certificate domain (e.g. `www.example.com`).
- **Delegated** → the provider is selected for the **resolved terminal target** (e.g. `abc123.acme-validation.net`).

This means a challenge delegated into a zone hosted by a *different* DNS provider is routed to the plugin that owns that zone. Propagation checks and cleanup also operate on the resolved name.

> ℹ️ Provider selection uses the AnyCA Gateway's Domain Validation configuration, which matches a configured (optionally wildcard) domain pattern one label at a time. Ensure the **delegation target's zone** is covered by a Domain Validation entry — e.g. a target of `abc123.acme-validation.net` needs a validator whose domain matches `*.acme-validation.net`.

#### Example (multi-level delegation across providers)

```text
Cert domain:      www.example.com                     (production zone, e.g. GoDaddy)
Challenge name:   _acme-challenge.www.example.com

DNS records (static, created once):
  _acme-challenge.www.example.com   CNAME  hop1.example.com          (GoDaddy)
  hop1.example.com                  CNAME  hop2.example.com          (GoDaddy)
  hop2.example.com                  CNAME  val.acme-zone.net         (points into the validation zone)

Resolution + placement:
  _acme-challenge.www.example.com → hop1 → hop2 → val.acme-zone.net  (terminal)
  Provider plugin selected for:   acme-zone.net  (the zone that owns val.acme-zone.net)
  TXT record created at:          val.acme-zone.net
  ACME CA queries _acme-challenge.www.example.com, follows the CNAMEs, finds the TXT ✅
```

> ℹ️ **Private/internal delegation zones:** set `DnsVerificationServer` to your authoritative DNS server IP. The `CnameResolver` honors it for the CNAME lookups; otherwise public resolvers (Google, Cloudflare, Quad9) are used.

</details>

<details>
<summary><strong>🔑 Provider Credentials &amp; Configuration</strong></summary>

Authentication methods and required configuration keys are specific to each DNS provider and are **documented in that provider's own plugin repository** — see the [`-dnsplugin` repositories](https://github.com/orgs/Keyfactor/repositories?q=-dnsplugin). Credentials and settings are supplied through the AnyCA Gateway's **Domain Validation** configuration for the chosen plugin, not in this ACME plugin's configuration.

</details>

<details>
<summary><strong>🏢 On-Premise / Private DNS</strong></summary>

On-premise and private DNS support (e.g. RFC 2136 dynamic updates against BIND/PowerDNS with TSIG) is provided by the corresponding DNS provider plugin — see its repository under the [`-dnsplugin` list](https://github.com/orgs/Keyfactor/repositories?q=-dnsplugin) for TSIG key generation, server/zone settings, and setup examples.

> ⚠️ **Private DNS Zones:** For private/local DNS zones (e.g., `.local`) that are not reachable via public resolvers, set `DnsVerificationServer` to your authoritative DNS server IP. This ACME plugin uses it both to verify TXT record propagation and to resolve CNAME delegation chains.

</details>

<details>
<summary><strong>🧩 Adding New DNS Providers</strong></summary>

DNS providers are independent plugins, so adding a new one requires **no change to this ACME plugin**. Publish a plugin that implements the AnyCA Gateway's `IDomainValidator` interface (create/cleanup the validation record for a domain), deploy it alongside the Gateway, and configure it under **Domain Validation**. The Gateway will resolve it per domain at enrollment time.

Use any existing plugin in the [`-dnsplugin` list](https://github.com/orgs/Keyfactor/repositories?q=-dnsplugin) as a reference implementation.

</details>

<details>
<summary><strong>🔒 Per-Domain DNS Provider Resolution</strong></summary>

You can configure **multiple DNS provider plugins** and the Gateway selects the appropriate one for each domain based on your **Domain Validation** configuration (matching a configured, optionally wildcard, domain pattern). This also means a single certificate with SANs across different zones/providers can be validated using different plugins, and CNAME-delegated challenges are routed to the plugin that owns the delegation target's zone (see **CNAME Delegation** above).

</details>

<details>
<summary><strong>🚫 No Offline Challenge Retry (Initial Release)</strong></summary>

In this initial release, there is **no background or offline retry** for ACME challenges that timeout. If DNS propagation takes too long and the challenge is not verified in time, the certificate **request will fail immediately**.

> ⚠️ However, in testing across all supported DNS providers and ACME services (e.g., Let's Encrypt, Google CAS, ZeroSSL, Buypass), propagation has been fast enough to avoid these timeouts in all observed cases.

</details>

---

### ACME Provider Configuration

Each ACME CA (Certificate Authority) has slightly different expectations for account creation and request handling. This plugin supports multiple providers and dynamically handles credentials based on your configuration.

<details>
<summary><strong>🧩 External Account Binding (EAB) Support</strong></summary>

Some providers **require** External Account Binding (EAB), which includes:
- `eabKid`: External Account Binding Key ID
- `eabHmacKey`: HMAC Key to sign the JWK thumbprint

Others **do not require EAB**, and can create accounts automatically with just an email address.

</details>

<details>
<summary><strong>✅ Supported Providers & Credential Expectations</strong></summary>

| Provider       | Directory URL                                                  | Requires EAB | Notes                                                                 |
|----------------|----------------------------------------------------------------|--------------|-----------------------------------------------------------------------|
| Let's Encrypt  | `https://acme-v02.api.letsencrypt.org/directory`              | ❌ No         | Free and public; account created using only an email address         |
| Buypass        | `https://api.buypass.com/acme/directory`                      | ❌ No         | Free and public; supports long-lived certs; no EAB required          |
| ZeroSSL        | `https://acme.zerossl.com/v2/DV90/directory`                  | ✅ Yes        | Requires EAB; keys available via [ZeroSSL Developer Portal](https://zerossl.com) |
| Google CAS     | `https://dv.acme-v02.api.pki.goog/directory`                  | ✅ Yes        | Requires EAB; keys issued via [Google CAS UI](https://console.cloud.google.com) |

> ⚠️ If a provider requires EAB and it is not supplied, the request will fail during account registration.

</details>

<details>
<summary><strong>📋 Configuration Fields (Per ACME Provider)</strong></summary>

These values are set in the Keyfactor Command Gateway Configuration UI for each ACME provider:

| Field         | Description                                       | Required        |
|---------------|---------------------------------------------------|-----------------|
| `directoryUrl`| The full ACME directory URL for the CA            | ✅ Yes          |
| `email`       | Account email address for ACME registration       | ✅ Yes          |
| `eabKid`      | External Account Binding Key ID (if applicable)   | 🚫 Only if EAB  |
| `eabHmacKey`  | HMAC key used to sign EAB binding (if applicable) | 🚫 Only if EAB  |

</details>

<details>
<summary><strong>🔐 How to Get EAB Credentials</strong></summary>

- **ZeroSSL**:  
  Log into your account and go to **"ACME EAB Credentials"** in the developer section.

- **Google CAS**:  
  Enable your CA Pool for ACME and generate EAB credentials under the **ACME Integration** tab in Google Cloud Console.

</details>

<details>
<summary><strong>⚙️ Plugin Behavior</strong></summary>

- If both `eabKid` and `eabHmacKey` are provided, they will be used to create the ACME account.
- If either is omitted and the provider requires it, account creation will fail.
- If neither is provided and the provider does not require EAB, the account will be created using only the email.

Each provider is configured in the JSON config under `acmeProviders`, and only **one provider** is active per enrollment.

</details>

---

### Account Storage and Signer Encryption

This ACME Gateway implementation uses a local file-based store to persist ACME accounts and their associated cryptographic signers. Accounts are cached on disk using a structured format, and signers (private keys) can be encrypted with a passphrase for enhanced security.

<details>
<summary><strong>📁 Account Directory Structure</strong></summary>

Each account is saved in its own directory within the configured storage path:

```
{AccountStoragePath}\{host}_{accountId}
```

**Default paths:**
- **Windows:** `%APPDATA%\AcmeAccounts\{host}_{accountId}`
- **Containers (when APPDATA unavailable):** `./AcmeAccounts\{host}_{accountId}`
- **Custom:** Set `AccountStoragePath` in the Gateway configuration

Where:
- `{host}` is the ACME directory host with dots replaced by dashes (e.g., `acme-zerossl-com`)
- `{accountId}` is the final segment of the account's KID URL

</details>

<details>
<summary><strong>📄 Files per Account</strong></summary>

- `Registration_v2`: Contains serialized `AccountDetails` in JSON format
- `Signer_v2`: Contains encrypted or plaintext signer key material, depending on passphrase usage
- `default_{host}.txt`: Tracks the default account for a given ACME directory host

</details>

<details>
<summary><strong>🔐 Encryption with Passphrase</strong></summary>

If the `SignerEncryptionPhrase` configuration value is set, the plugin encrypts signer files (`Signer_v2`) using AES with a PBKDF2-derived key and IV. The encrypted data includes a prepended salt and IV to support cross-platform decryption.

```text
[Salt (16 bytes)] [IV (16 bytes)] [AES-CBC encrypted signer JSON]
```

The encryption ensures that even if the account files are accessed on disk, the private keys remain unreadable without the configured passphrase.

</details></details>

<details>
<summary><strong>🔗 External Account Binding (EAB)</strong></summary>

For ACME providers requiring EAB (e.g., ZeroSSL, Google CAS), the gateway constructs a manually signed JWS payload containing:

- Protected Header: `alg`, `kid`, `url`
- Payload: Public JWK of the account signer
- Signature: HMAC using `eabHmacKey`

This JWS is included during account creation to bind the account to the pre-provisioned identity provided by the CA.

</details>

<details>
<summary><strong>⚙️ Algorithm Support</strong></summary>

- Signers support `ES256`, `ES384`, `ES512` (ECDSA) and `RS256`, `RS384`, `RS512` (RSA)
- EAB HMAC support includes `HS256`, `HS384`, `HS512`

If `ES256` key generation fails (e.g., due to platform constraints), the system automatically falls back to `RS256`.

</details>

### Account Caching and Auto-Creation

On startup or during enrollment/sync, the plugin:

1. Attempts to load a cached account for the specified ACME directory.
2. If no account is found, it automatically creates a new one, using EAB if configured.
3. The new account is saved to disk and set as default for future use.

<details>
<summary><strong>🔗 External Account Binding (EAB)</strong></summary>

For ACME providers requiring EAB (e.g., ZeroSSL, Google CAS), the gateway constructs a manually signed JWS payload containing:

- Protected Header: `alg`, `kid`, `url`
- Payload: Public JWK of the account signer
- Signature: HMAC using `eabHmacKey`

This JWS is included during account creation to bind the account to the pre-provisioned identity provided by the CA.

</details>

<details>
<summary><strong>🔧 Algorithm Support</strong></summary>

- Signers support `ES256`, `ES384`, `ES512` (ECDSA) and `RS256`, `RS384`, `RS512` (RSA)
- EAB HMAC support includes `HS256`, `HS384`, `HS512`

If `ES256` key generation fails (e.g., due to platform constraints), the system automatically falls back to `RS256`.

</details>

### Network and File System Requirements

This section outlines all required ports, file access, permissions, and validation behaviors for operating the ACME Gateway Plugin in a Keyfactor Orchestrator environment.

<details>
<summary><strong>🔌 Port Usage</strong></summary>

#### Incoming Connections

- **None.** This plugin does not expose any HTTP or network listeners.

#### Outgoing Connections

| Protocol | Port | Target                       | Purpose                                             |
|----------|------|------------------------------|-----------------------------------------------------|
| HTTPS    | 443  | ACME Directory URL           | Connect to the ACME CA for account, challenge, and certificate operations |
| HTTPS    | 443  | DNS Provider APIs            | Used for DNS-01 challenge automation (Google DNS, AWS, etc.) |
| TCP      | 53   | On-Premise DNS Server        | RFC 2136 dynamic updates (BIND/Microsoft DNS) - only if using RFC 2136 provider |

</details>

<details>
<summary><strong>💾 File System Requirements</strong></summary>

#### Directory Layout

| Path                                               | Purpose                                      |
|----------------------------------------------------|----------------------------------------------|
| `%APPDATA%\AcmeAccounts\` or `AccountStoragePath`  | Base path for ACME account storage (configurable) |
| `{base}\{account_id}\Registration_v2`              | Contains serialized ACME account metadata    |
| `{base}\{account_id}\Signer_v2`                    | Contains the encrypted private signer key    |
| `{base}\default_{host}.txt`                        | Stores the default account pointer for a given directory |

#### File Access & Permissions

| Path                     | Operation | Required Permission |
|--------------------------|-----------|---------------------|
| Account directory        | Create    | `Write`             |
| Account files            | Read/Write| `Read`, `Write`     |

- Files may be optionally encrypted using AES if a passphrase is configured.
- Ensure the service account under which the orchestrator runs has read/write access to the configured base path.
- For containers, mount a persistent volume to the `AccountStoragePath` to preserve accounts across restarts.

</details>

<details>
<summary><strong>👤 Windows Account Permissions</strong></summary>

- The orchestrator service account (usually `NT AUTHORITY\SYSTEM` or a custom `Network Service`) must have:
  - File I/O permissions to read/write within the configured base directory.
  - Network access to ACME CA endpoints and DNS APIs over HTTPS.
  - DNS provider credentials (Cloudflare API token, Google credentials, etc.) stored securely.

</details>

<details>
<summary><strong>🌐 DNS Propagation Check Behavior</strong></summary>

- **Initial Release Behavior**:
  - DNS challenge propagation is checked during the interactive enrollment phase only.
  - If propagation takes too long (> 60s), the request will fail. No deferred background polling occurs.
  - There is **no offline retry mechanism** (e.g., for sync jobs) to pick up completed validations that succeeded after a delay.

- **Future Considerations**:
  - Support for file-based or database-backed challenge persistence may be added to allow background sync to re-check and finalize challenge state.

</details>

---

### Container Deployment

This section covers configuration options specific to containerized deployments (Docker, Kubernetes, etc.).

<details>
<summary><strong>📁 Configurable Account Storage Path</strong></summary>

By default, the plugin stores ACME accounts in `%APPDATA%\AcmeAccounts` on Windows. In containerized environments, use the `AccountStoragePath` configuration option:

| Environment | Recommended Path |
|-------------|------------------|
| Docker/Kubernetes | `/data/AcmeAccounts` (mounted volume) |
| Windows Container | `C:\AcmeData\AcmeAccounts` |

If `AccountStoragePath` is not set and `%APPDATA%` is unavailable, the plugin defaults to `./AcmeAccounts` relative to the working directory.

</details>

<details>
<summary><strong>🌐 DNS Provider Authentication in Containers</strong></summary>

DNS provider credentials in containerized environments are handled by each **DNS provider plugin**, not by this ACME plugin. Options such as cloud-native identity (GKE Workload Identity, EKS IRSA, AKS Pod Identity), mounted key files, or config-supplied secrets depend on the provider — see the relevant plugin under the [`-dnsplugin` list](https://github.com/orgs/Keyfactor/repositories?q=-dnsplugin) for its supported container authentication methods.

</details>

<details>
<summary><strong>☸️ Kubernetes Deployment Considerations</strong></summary>

When deploying in Kubernetes:

1. **Persistent Storage**: Use a PersistentVolumeClaim for `AccountStoragePath` to preserve ACME accounts across pod restarts.
2. **Cloud Provider Identity**: Leverage Workload Identity (GKE), IAM Roles for Service Accounts (EKS), or Pod Identity (AKS) for DNS provider authentication.

**Example PersistentVolumeClaim:**
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: acme-accounts
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi
```

</details>


## Gateway Registration

Each ACME CA issues certificates that chain to a specific intermediate and root certificate. For trust validation and proper integration with the Keyfactor Gateway, the following steps are required for **every ACME CA** used in your environment.

---

### 🔍 Retrieving Root and Intermediate Certificates

Here is how to obtain the root and intermediate CA certificates from supported ACME providers:

#### Let's Encrypt

Let's Encrypt periodically rotates its root and intermediate certificates. Always refer to their official certificates page for the current active chain.

**How to Get:**
- Browse to: https://letsencrypt.org/certificates/
- Identify the currently active **root** and **intermediate** certificates listed on that page.
- Download both certificates in **PEM format**.

#### Google Certificate Authority Service (CAS)

- **Root** and **Intermediate** are custom per CA Pool.

**How to Get:**
1. In the [Google Cloud Console](https://console.cloud.google.com/security/privateca), navigate to your CA pool.
2. Click the CA name and go to the **Certificates** tab.
3. Download the **root** and **intermediate** certificates for the issuing CA in PEM format.

#### ZeroSSL

- **Root**: USERTrust RSA Certification Authority
- **Intermediate**: ZeroSSL RSA Domain Secure Site CA

**How to Get:**
- Visit: https://zerossl.com
- Download the full certificate chain in PEM format.
- Extract individual certs if needed using OpenSSL or a text editor.

#### Buypass

- **Root**: Buypass Class 3 Root CA
- **Intermediate**: Buypass Class 3 CA 1 / G2 (depends on issuance)

**How to Get:**
- Go to: https://www.buypass.com
- Download both root and intermediate in PEM or DER format.

---

### 🧩 Installing Certificates on the Keyfactor Gateway Server

Once downloaded, the **root and intermediate certificates must be installed** in the proper Windows certificate stores on the Gateway server.

#### Steps:

1. **Open** `certlm.msc` (Local Computer Certificates)
2. Install the **Root CA certificate** into:
   - `Trusted Root Certification Authorities` → `Certificates`
3. Install the **Intermediate CA certificate** into:
   - `Intermediate Certification Authorities` → `Certificates`

You can import certificates using the GUI or PowerShell:

```powershell
Import-Certificate -FilePath "C:\path\to\intermediate.crt" -CertStoreLocation "Cert:\LocalMachine\CA"
Import-Certificate -FilePath "C:\path\to\root.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
```

---

### 🔑 Using the Intermediate Thumbprint

When registering a new CA in Keyfactor Command:

- You must specify the **thumbprint** of the Intermediate CA certificate.
- This is used to associate issued certificates with the correct issuing chain.

**How to Get the Thumbprint:**

1. In `certlm.msc`, open the certificate under **Intermediate Certification Authorities**.
2. Go to **Details** tab → Scroll to **Thumbprint**.
3. Copy the hex string (ignore spaces).

---

⚠️ All certificate chains must be trusted by the Gateway OS. If the intermediate is missing or untrusted, issuance will fail or returned certificates may not chain properly.

