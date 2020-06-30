# Import standard libraries
import logging
import sys
import requests
import json
import time
import base64
import hashlib
from uuid import uuid4

# Import third-party libraries
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from azure.identity import DefaultAzureCredential 
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

# Set variables
TENANT_ID = '' # Tenant id such as myorg.onmicrosoft.com
CLIENT_ID = '' # Client ID of service principal
KEY_VAULT_URL = '' # Key Vault URL
CERTIFICATE_NAME = ''# Name of the certificate
RESOURCE = '' # Resource you want to access such as https://management.azure.com

# Create a logging mechanism
def enable_logging():
    stdout_handler = logging.StreamHandler(sys.stdout)
    handlers = [stdout_handler]
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers = handlers
    )

# Get an access token using a certificate from Key Vault
def obtain_access_token(key_vault_url, msi_credential, certificate_name, tenant_id, client_id, resource):

    # Get certificate from Key Vault, load the DER certificate it returns, and calculate the thumbprint
    cert_client = CertificateClient(key_vault_url, msi_credential)
    result = (cert_client.get_certificate(certificate_name)).cer
    cert= load_der_x509_certificate(result,backend=default_backend())
    thumbprint = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).decode('UTF-8')
    
    # Create the headers for the JWT
    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "x5t":thumbprint
    }
    encoded_header = (base64.urlsafe_b64encode(bytes(json.dumps(headers),'UTF-8'))).decode('UTF-8')

    # Generate a nonce
    nonce = uuid4().hex

    # Create the JWT payload
    claims = {
        "aud":f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
        "iss":client_id,
        "sub":client_id,
        "jti":nonce,
        "nbf":int(time.time()),
        "exp":int(time.time()+(7*86400))
    }
    encoded_claims = (base64.urlsafe_b64encode(bytes(json.dumps(claims), 'UTF-8'))).decode('UTF-8').rstrip('=')

    # Issue the request to Key Vault to sign the data
    key_client = KeyClient(key_vault_url, msi_credential)
    key = key_client.get_key(certificate_name)
    crypto_client = CryptographyClient(key, credential=msi_credential)
    data_hash = hashlib.sha256(bytes((encoded_header + '.' + encoded_claims),'UTF-8')).digest()
        
    # Use Key Vault to calculate a signature using RSASSA-PKCS1-v1_5 using SHA-512
    jws_signature = (crypto_client.sign(SignatureAlgorithm.rs256, data_hash)).signature
    encoded_jws_signature = (base64.urlsafe_b64encode(jws_signature)).decode('UTF-8').rstrip('=')
    assertion = encoded_header + '.' + encoded_claims + '.' + encoded_jws_signature
    payload = {
        "grant_type":"client_credentials",
        "client_id":client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":assertion,
        "resource":resource
    }
    
    # Post the request for the access token
    result = requests.post(
        url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
        data=payload
    )

    # Validate that access token was returned
    if result.status_code == 200:
        logging.info('Access token successfully obtained')
        return ((json.loads(result.text))['access_token'])
    else:
        error = json.loads(result.text)
        logging.error('Unable to obtain access token')
        logging.error(f"Error was: {error['error']}")
        logging.error(f"Error description was: {error['error_description']}")
        logging.error(f"Error correlation_id was: {error['correlation_id']}")
        raise Exception('Failed to obtain access token')

    
def main():
    try:

        # Setup logging
        enable_logging()

        # Obtain a credential from the system-assigned managed identity
        msi_credential = DefaultAzureCredential()

        # Obtain an access token
        access_token = obtain_access_token(
            key_vault_url = KEY_VAULT_URL,
            msi_credential = msi_credential,
            certificate_name = CERTIFICATE_NAME,
            tenant_id = TENANT_ID,
            client_id = CLIENT_ID,
            resource = RESOURCE
        )

        print(access_token)

    except Exception:
        logging.error('Execution error: ', exc_info=True)

if __name__ == "__main__":
    main()
