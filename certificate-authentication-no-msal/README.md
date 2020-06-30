# Azure Key Vault and Client Certificate with non-exportable Private key
This solution demonstrates how a client certificate stored in [Azure's Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/) can be retrieved using an [Azure Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) and then be used to query the Azure Resource Manager API.  It covers the use case where the certificate has a non-exportable private key so [Microsoft Authentication Library (MSAL)](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-overview) library cannot be used.

It is written in Python 3 and uses the [Microsft Azure Python SDKs](https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-overview).

## What problem does this solve?
Secure credential management remains a challenge in the public cloud.  Azure Key Vault addresses this challenge by providing secure storage for keys, secrets, and certificates which can then be made programmatically available to applications.  The certificates stored in Azure Key Vault can be used for operations like authenticating to a third-party API.  This code demonstrates how to authenticate against Azure Active Directory to get an access token for the Azure Resource Manager (ARM) API using a service principal configured for certificate authentication.
## Requirements

### Resources
* A managed identity assigned to a resource running in Azure
* An instance of Azure Key Vault where managed identity has been granted the [Get Key, Get Certificate, and Sign permissions](https://docs.microsoft.com/en-us/azure/key-vault/general/secure-your-key-vault)
* A client certificate that has been [imported](https://docs.microsoft.com/en-us/azure/key-vault/certificates/tutorial-import-certificate) or created in Azure Key Vault and has been configured a non-exportable private key.
* A standard Azure AD [service principal](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals) which has been configured to use the (certificate for authentication)[https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#certificates-and-secrets].

## Setup

1. Use pip to install the required libraries.
2. Modify __init__.py to provide the required variables.
3. Run the solution.
