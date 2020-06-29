# Import standard libraries
import os
import sys
import re
import logging

# Import third-party libraries
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from msal import ConfidentialClientApplication
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient


# Setup some sample variables
KEY_VAULT_URL = # Your Key Vault URL
CERTIFICATE_NAME = # The name of the certificate in Azure Key Vault
TENANT_NAME = # The name of your tenant
CLIENT_ID = # The client id of the service principal you are testing with
SCOPES = ['https://management.azure.com//.default']

# Create a logging mechanism
def enable_logging():
    stdout_handler = logging.StreamHandler(sys.stdout)
    handlers = [stdout_handler]
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers = handlers
    )

# obtain an access token
def get_sp_access_token(client_id,client_credential,tenant_name,scopes):
    logging.info('Attempting to obtain an access token...')
    result = None
    app = ConfidentialClientApplication(
        client_id = client_id,
        client_credential= client_credential,
        authority = f"https://login.microsoftonline.com/{tenant_name}"
    )
    result = app.acquire_token_for_client(scopes=scopes)

    if "access_token" in result:
        logging.info('Access token successfully acquired')
        return result['access_token']
    else:
        logging.error('Unable to obtain access token')
        logging.error(f"Error was: {result['error']}")
        logging.error(f"Error description was: {result['error_description']}")
        logging.error(f"Error correlation_id was: {result['correlation_id']}")
        raise Exception('Failed to obtain access token')

def main():
    try:

        # Enable logging
        enable_logging()

        # Obtain a credential from the system-assigned managed identity
        msi_credential = DefaultAzureCredential()

        # Get the private key and certificate in PEM format from Key Vault
        secret_client = SecretClient(KEY_VAULT_URL, msi_credential)
        myazuresecret = secret_client.get_secret(CERTIFICATE_NAME)

        # Extract the private key and certificate from the response
        private_key = (re.findall("-----BEGIN.*END PRIVATE KEY-----",myazuresecret.value, re.DOTALL))[0]
        public_certificate = (re.findall("-----BEGIN CERTIFICATE.*END CERTIFICATE-----",myazuresecret.value, re.DOTALL))[0]

        # Create an X509 object and calculate the thumbprint
        cert = load_pem_x509_certificate(data=bytes(public_certificate, 'UTF-8'),backend=default_backend())
        thumbprint = (cert.fingerprint(hashes.SHA1()).hex())

        # Obtain an access token
        mytoken = get_sp_access_token(
            client_id = CLIENT_ID,
            client_credential = {
                "private_key":private_key,
                "thumbprint":thumbprint,
                "public_certificate":public_certificate
            },
            tenant_name = TENANT_NAME,
            scopes = SCOPES
        )

        print(mytoken)
    
    except Exception:
        logging.error('Execution error: ', exc_info=True)

if __name__ == "__main__":
    main()

