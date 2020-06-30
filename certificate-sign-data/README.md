# Azure Key Vault and signing demo in Python
This solution demonstrates how a client certificate stored in [Azure's Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/) can be retrieved using an [Azure Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) and used to sign data.

It is written in Python 3 and uses the [Microsft Azure Python SDKs](https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-overview).

## What problem does this solve?
Secure credential management remains a challenge in the public cloud.  Azure Key Vault addresses this challenge by providing secure storage for keys, secrets, and certificates which can then be made programmatically available to applications.  The certificates stored in Azure Key Vault can be used for operations like signing and verifying a digitally signed data set.  This code demonstrates how to use the sign function of Azure Key Vault to sign a data set and uses verifies the digital signature using the [Python cryptography library](https://github.com/pyca/cryptography)

## Requirements

### Resources
* A managed identity assigned to a resource running in Azure
* An instance of Azure Key Vault where managed identity has been granted the [Get Key, Get Certificate, Sign, and Verify permissions](https://docs.microsoft.com/en-us/azure/key-vault/general/secure-your-key-vault)
* A client certificate that has been [imported](https://docs.microsoft.com/en-us/azure/key-vault/certificates/tutorial-import-certificate) or created in Azure Key Vault.

## Setup

1. Use pip to install the required libraries.
2. Modify __init__.py to provide the required variables.
3. Run the solution.
