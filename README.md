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


TODO Overview is a required section

## Compatibility

The Acme AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.

## Support
The Acme AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

TODO Requirements is a required section

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

2. TODO Certificate Template Creation Step is an optional section. If this section doesn't seem necessary on initial glance, please delete it. Refer to the docs on [Confluence](https://keyfactor.atlassian.net/wiki/x/SAAyHg) for more info

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. TODO Custom Enrollment Parameter Creation Step is an optional section. If this section doesn't seem necessary on initial glance, please delete it. Refer to the docs on [Confluence](https://keyfactor.atlassian.net/wiki/x/SAAyHg) for more info



## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).