<h1 align="center" style="border-bottom: none">
    Acme AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/acme-provider-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/acme-provider-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/acme-provider-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/acme-provider-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


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

### 🌐 Supported DNS Providers (Initial Release)
DNS-01 challenge automation is supported through the following providers:
- **Google Cloud DNS**
- **AWS Route 53**
- **Azure DNS**
- **Cloudflare**
- **NS1**

Additional DNS providers can be added by extending the included `IDnsProvider` interface.

---

### 🔁 Enrollment Flow Summary

```text
1. Keyfactor Gateway submits CSR and SAN metadata to plugin.
2. Plugin initializes ACME client and creates a new order.
3. For each domain:
   a. Retrieve DNS-01 challenge.
   b. Use the configured DNS provider to publish challenge record.
   c. Wait for DNS propagation and validate record.
   d. Notify ACME provider to trigger validation.
4. Once all challenges are valid, finalize the order using CSR.
5. Download the signed certificate from ACME provider.
6. Return PEM certificate to the Gateway.
```

The plugin uses a modular design that separates ACME communication logic and DNS challenge automation, allowing for future extensibility in both areas.

> ⚠️ Revocation, certificate synchronization, and renewal tracking are intentionally **not implemented** in this plugin. All lifecycle tracking must be handled externally (e.g., via Keyfactor monitoring or Gateway automation).

## Compatibility

The Acme AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.

## Support
The Acme AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

### DNS Providers

This plugin automates DNS-01 challenges using pluggable DNS provider implementations. These providers create and remove TXT records to prove domain control to ACME servers.

<details>
<summary><strong>✅ Supported DNS Providers (Initial Release)</strong></summary>

| Provider     | Auth Methods Supported                        | Config Keys Required                                  |
|--------------|-----------------------------------------------|--------------------------------------------------------|
| Google DNS   | Service Account Key or ADC                    | `Google_ServiceAccountKeyPath`, `Google_ProjectId`     |
| AWS Route 53 | Access Key/Secret or IAM Role                 | `AwsRoute53_AccessKey`, `AwsRoute53_SecretKey`         |
| Azure DNS    | Client Secret or Managed Identity             | `Azure_TenantId`, `Azure_ClientId`, `Azure_ClientSecret`, `Azure_SubscriptionId` |
| Cloudflare   | API Token                                     | `Cloudflare_ApiToken`                                  |
| NS1          | API Key                                       | `Ns1_ApiKey`                                           |

</details>

<details>
<summary><strong>⏱ DNS Propagation Logic</strong></summary>

Before submitting ACME challenges, the plugin verifies DNS propagation using multiple public resolvers (Google, Cloudflare, OpenDNS, Quad9). A record must be visible on **at least 3 servers** to proceed, with up to **3 retries** spaced by 10 seconds.

This logic is handled by the `DnsVerificationHelper` class and ensures a high-confidence validation before proceeding.

</details>

<details>
<summary><strong>🔑 Credential Flow</strong></summary>

Each provider supports multiple credential strategies:

- **Google DNS**:  
  - ✅ **Service Account Key** (via `Google_ServiceAccountKeyPath`)  
  - ✅ **Application Default Credentials** (e.g., GCP Workload Identity or developer auth)

- **AWS Route 53**:  
  - ✅ **Access/Secret Keys** (`AwsRoute53_AccessKey`, `AwsRoute53_SecretKey`)  
  - ✅ **IAM Role via EC2 Instance Metadata** (no explicit credentials)

- **Azure DNS**:  
  - ✅ **Client Secret** (explicit `TenantId`, `ClientId`, `ClientSecret`)  
  - ✅ **Managed Identity** or environment-based credentials via `DefaultAzureCredential`

- **Cloudflare**:  
  - ✅ **Bearer API Token** for zone-level DNS control

- **NS1**:  
  - ✅ **API Key** passed in header `X-NSONE-Key`

</details>

<details>
<summary><strong>🧩 Adding New DNS Providers</strong></summary>

To add support for new DNS services:

1. Implement the `IDnsProvider` interface:
   ```csharp
   public interface IDnsProvider
   {
       Task<bool> CreateRecordAsync(string recordName, string txtValue);
       Task<bool> DeleteRecordAsync(string recordName);
   }
   ```

2. Register the new provider in the `DnsProviderFactory`:
   ```csharp
   case "yourprovider":
       return new YourCustomDnsProvider(config.YourProviderConfigValues...);
   ```

3. Use zone detection logic similar to `GoogleDnsProvider`, `AzureDnsProvider`, or `Ns1DnsProvider`.

Each provider is instantiated dynamically based on the `DnsProvider` field in the `AcmeClientConfig`.

> 🔁 This modular DNS system ensures challenge automation works across cloud providers and is easily extensible.

</details>

<details>
<summary><strong>🔒 CA-Level DNS Provider Binding</strong></summary>

Each ACME/DNS combination is supported **at the CA level**, meaning that only **one DNS provider** is configured per CA entry in Keyfactor. This ensures a clear and isolated challenge path for each ACME CA connector instance.

If you need to support multiple DNS zones/providers (e.g., both AWS and Cloudflare), configure **separate CA entries**, each with its own DNS provider configuration.

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

Each account is saved in its own directory within:

```
%APPDATA%\AcmeAccounts\{host}_{accountId}
```

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

</details>

<details>
<summary><strong>💾 File System Requirements</strong></summary>

#### Directory Layout

| Path                                               | Purpose                                      |
|----------------------------------------------------|----------------------------------------------|
| `%APPDATA%\AcmeAccounts\`                        | Default base path for ACME account storage   |
| `AcmeAccounts\{account_id}\Registration_v2`      | Contains serialized ACME account metadata    |
| `AcmeAccounts\{account_id}\Signer_v2`            | Contains the encrypted private signer key    |
| `AcmeAccounts\default_{host}.txt`                 | Stores the default account pointer for a given directory |

#### File Access & Permissions

| Path                     | Operation | Required Permission |
|--------------------------|-----------|---------------------|
| Account directory        | Create    | `Write`             |
| Account files            | Read/Write| `Read`, `Write`     |

- Files may be optionally encrypted using AES if a passphrase is configured.
- Ensure the service account under which the orchestrator runs has read/write access to `%APPDATA%` or the custom configured base path.

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

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [Acme AnyCA Gateway REST plugin](https://github.com/Keyfactor/acme-provider-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0`) to the Extensions directory:

    ```shell
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    ```

    > The directory containing the Acme AnyCA Gateway REST plugin DLLs (`net6.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the Acme plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        TODO Gateway Registration is a required section

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **DirectoryUrl** - ACME directory URL (e.g. Let's Encrypt, ZeroSSL, etc.) 
        * **Email** - Email for ACME account registration. 
        * **EabKid** - External Account Binding Key ID (optional) 
        * **EabHmacKey** - External Account Binding HMAC key (optional) 
        * **SignerEncryptionPhrase** - Used to encrypt singer information when account is saved to disk (optional) 
        * **DnsProvider** - DNS Provider to use for ACME DNS-01 challenges (options Google, Cloudflare, AwsRoute53, Azure, Ns1) 
        * **Google_ServiceAccountKeyPath** - Google Cloud DNS: Path to service account JSON key file only if using Google DNS (Optional) 
        * **Google_ProjectId** - Google Cloud DNS: Project ID only if using Google DNS (Optional) 
        * **Cloudflare_ApiToken** - Cloudflare DNS: API Token only if using Cloudflare DNS (Optional) 
        * **Azure_ClientId** - Azure DNS: ClientId only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **Azure_ClientSecret** - Azure DNS: ClientSecret only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **Azure_SubscriptionId** - Azure DNS: SubscriptionId only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **Azure_TenantId** - Azure DNS: TenantId only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **AwsRoute53_AccessKey** - Aws DNS: Access Key only if not using AWS DNS and default AWS Chain Creds on AWS (Optional) 
        * **AwsRoute53_SecretKey** - Aws DNS: Secret Key only if using AWS DNS and not using default AWS Chain Creds on AWS (Optional) 
        * **Ns1_ApiKey** - Ns1 DNS: Api Key only if Using Ns1 DNS (Optional) 

2. Define [Certificate Profiles](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCP-Gateway.htm) and [Certificate Templates](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) for the Certificate Authority as required. One Certificate Profile must be defined per Certificate Template. It's recommended that each Certificate Profile be named after the Product ID. The Acme plugin supports the following product IDs:

    * **default**

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.


## Compatibility

The Acme AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.

## Support
The Acme AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [Acme AnyCA Gateway REST plugin](https://github.com/Keyfactor/acme-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0`) to the Extensions directory:

    ```shell
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    ```

    > The directory containing the Acme AnyCA Gateway REST plugin DLLs (`net6.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the Acme plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        TODO Gateway Registration is a required section

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **DirectoryUrl** - ACME directory URL (e.g. Let's Encrypt, ZeroSSL, etc.) 
        * **Email** - Email for ACME account registration. 
        * **EabKid** - External Account Binding Key ID (optional) 
        * **EabHmacKey** - External Account Binding HMAC key (optional) 
        * **SignerEncryptionPhrase** - Used to encrypt singer information when account is saved to disk (optional) 
        * **DnsProvider** - DNS Provider to use for ACME DNS-01 challenges (options Google, Cloudflare, AwsRoute53, Azure, Ns1) 
        * **Google_ServiceAccountKeyPath** - Google Cloud DNS: Path to service account JSON key file only if using Google DNS (Optional) 
        * **Google_ProjectId** - Google Cloud DNS: Project ID only if using Google DNS (Optional) 
        * **Cloudflare_ApiToken** - Cloudflare DNS: API Token only if using Cloudflare DNS (Optional) 
        * **Azure_ClientId** - Azure DNS: ClientId only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **Azure_ClientSecret** - Azure DNS: ClientSecret only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **Azure_SubscriptionId** - Azure DNS: SubscriptionId only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **Azure_TenantId** - Azure DNS: TenantId only if using Azure DNS and Not Managed Itentity in Azure (Optional) 
        * **AwsRoute53_AccessKey** - Aws DNS: Access Key only if not using AWS DNS and default AWS Chain Creds on AWS (Optional) 
        * **AwsRoute53_SecretKey** - Aws DNS: Secret Key only if using AWS DNS and not using default AWS Chain Creds on AWS (Optional) 
        * **Ns1_ApiKey** - Ns1 DNS: Api Key only if Using Ns1 DNS (Optional) 

2. The ACME Gateway Plugin does not require specific certificate templates to be mapped to individual ACME providers in Keyfactor. Instead, you have the flexibility to define templates based on your organization's needs or the specific capabilities of the ACME provider.

    Key considerations:
    - There is no required or hardcoded template for enrollment.
    - The **default template** configured in Keyfactor Command will work for the majority of cases.
    - You may create additional templates with specific **key types and sizes** (e.g., RSA 2048, RSA 4096, ECC P-256) to match the requirements or limitations of your chosen ACME CA.

    This allows you to support a variety of use cases or certificate profiles without being tightly coupled to the ACME provider’s template logic. The ACME Gateway simply passes the CSR (generated using the selected Keyfactor template) to the ACME provider.

    > ✅ The plugin will accept any Keyfactor template that produces a valid CSR in a format compatible with the selected ACME provider.

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

## Root CA Configuration

Each ACME CA issues certificates that chain to a specific intermediate and root certificate. For trust validation and proper integration with the Keyfactor Gateway, the following steps are required for **every ACME CA** used in your environment.

---

### 🔍 Retrieving Root and Intermediate Certificates

Here is how to obtain the root and intermediate CA certificates from supported ACME providers:

#### Let's Encrypt

- **Root**: ISRG Root X1
- **Intermediate**: R3

**How to Get:**
- Browse to: https://letsencrypt.org/certificates/
- Download both the **ISRG Root X1** and **R3 Intermediate Certificate (PEM format)**.

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

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).