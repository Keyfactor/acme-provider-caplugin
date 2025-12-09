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

### 🌐 Supported DNS Providers
DNS-01 challenge automation is supported through the following providers:
- **Google Cloud DNS**
- **AWS Route 53**
- **Azure DNS**
- **Cloudflare**
- **NS1**
- **Infoblox**
- **RFC 2136 Dynamic DNS** (BIND with TSIG authentication)

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
<summary><strong>✅ Supported DNS Providers</strong></summary>

| Provider     | Auth Methods Supported                        | Config Keys Required                                  |
|--------------|-----------------------------------------------|--------------------------------------------------------|
| Google DNS   | Service Account Key or ADC                    | `Google_ServiceAccountKeyPath`, `Google_ProjectId`     |
| AWS Route 53 | Access Key/Secret or IAM Role                 | `AwsRoute53_AccessKey`, `AwsRoute53_SecretKey`         |
| Azure DNS    | Client Secret or Managed Identity             | `Azure_TenantId`, `Azure_ClientId`, `Azure_ClientSecret`, `Azure_SubscriptionId` |
| Cloudflare   | API Token                                     | `Cloudflare_ApiToken`                                  |
| NS1          | API Key                                       | `Ns1_ApiKey`                                           |
| Infoblox     | Username/Password (Basic Auth)                | `Infoblox_Host`, `Infoblox_Username`, `Infoblox_Password` |
| RFC 2136     | TSIG Key (BIND)                               | `Rfc2136_Server`, `Rfc2136_Zone`, `Rfc2136_TsigKeyName`, `Rfc2136_TsigKey` |

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

- **Infoblox**:
  - ✅ **Username/Password** (Basic Auth via WAPI REST API)
  - Optional: `Infoblox_WapiVersion` (defaults to `2.12`)
  - Optional: `Infoblox_IgnoreSslErrors` for self-signed certificates

- **RFC 2136 (BIND)**:
  - ✅ **TSIG Key** for secure dynamic DNS updates
  - Supports algorithms: `hmac-md5`, `hmac-sha1`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`
  - Default algorithm: `hmac-sha256` (recommended)
  - Optional: `Rfc2136_Port` (defaults to `53`)

</details>

<details>
<summary><strong>🏢 On-Premise DNS (RFC 2136)</strong></summary>

The RFC 2136 provider enables ACME DNS-01 challenges with on-premise DNS servers that support dynamic updates, including:

- **BIND** (Berkeley Internet Name Domain)
- **Microsoft DNS** (Windows Server DNS)
- **PowerDNS** (with dynamic update support)
- Any DNS server supporting RFC 2136 with TSIG authentication

#### Configuration Requirements

| Field | Description | Required |
|-------|-------------|----------|
| `Rfc2136_Server` | DNS server hostname or IP address | ✅ Yes |
| `Rfc2136_Zone` | DNS zone to update (e.g., `example.com`) | ✅ Yes |
| `Rfc2136_TsigKeyName` | TSIG key name (e.g., `acme-update-key`) | ✅ Yes |
| `Rfc2136_TsigKey` | Base64-encoded TSIG secret key | ✅ Yes |
| `Rfc2136_TsigAlgorithm` | TSIG algorithm (default: `hmac-sha256`) | Optional |
| `Rfc2136_Port` | DNS server port (default: `53`) | Optional |

#### Generating TSIG Keys

**For BIND:**
```bash

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [Acme AnyCA Gateway REST plugin](https://github.com/Keyfactor/acme-provider-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the Acme AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the Acme plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

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

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **DirectoryUrl** - ACME directory URL (e.g. Let's Encrypt, ZeroSSL, etc.) 
        * **Email** - Email for ACME account registration. 
        * **EabKid** - External Account Binding Key ID (optional) 
        * **EabHmacKey** - External Account Binding HMAC key (optional) 
        * **SignerEncryptionPhrase** - Used to encrypt singer information when account is saved to disk (optional)
        * **DnsProvider** - DNS Provider to use for ACME DNS-01 challenges (options: Google, Cloudflare, AwsRoute53, Azure, Ns1, Rfc2136, Infoblox)
        * **SignerEncryptionPhrase** - Used to encrypt singer information when account is saved to disk (optional) 
        * **DnsProvider** - DNS Provider to use for ACME DNS-01 challenges (options: Google, Cloudflare, AwsRoute53, Azure, Ns1, Rfc2136) 
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
        * **Rfc2136_Server** - RFC 2136 DNS: Server hostname or IP address (Optional)
        * **Rfc2136_Port** - RFC 2136 DNS: Server port (default 53) (Optional)
        * **Rfc2136_Zone** - RFC 2136 DNS: Zone name (e.g., example.com) (Optional)
        * **Rfc2136_TsigKeyName** - RFC 2136 DNS: TSIG key name for authentication (Optional)
        * **Rfc2136_TsigKey** - RFC 2136 DNS: TSIG key (base64 encoded) for authentication (Optional)
        * **Rfc2136_TsigAlgorithm** - RFC 2136 DNS: TSIG algorithm (default hmac-sha256) (Optional)
        * **Infoblox_Host** - Infoblox DNS: API URL (e.g., https://infoblox.example.com/wapi/v2.12) only if using Infoblox DNS (Optional)
        * **Infoblox_Username** - Infoblox DNS: Username for authentication only if using Infoblox DNS (Optional)
        * **Infoblox_Password** - Infoblox DNS: Password for authentication only if using Infoblox DNS (Optional)
        * **DnsVerificationServer** - DNS server to use for verifying TXT record propagation. For private/local DNS zones, set this to your authoritative DNS server IP (e.g., 10.3.10.37). Leave empty to use public DNS servers (Google, Cloudflare, etc.).

2. Define [Certificate Profiles](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCP-Gateway.htm) and [Certificate Templates](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) for the Certificate Authority as required. One Certificate Profile must be defined per Certificate Template. It's recommended that each Certificate Profile be named after the Product ID. The Acme plugin supports the following product IDs:

    * **default**

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.


## Compatibility

The Acme AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).