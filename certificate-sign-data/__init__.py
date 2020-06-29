# Import standard libraries
import os
import sys
import logging
import json
import base64
import hashlib

# Import third-party libraries
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from azure.identity import DefaultAzureCredential 
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

# Setup some sample variables
KEY_VAULT_URL = '' # The Key Vault URL 
CERTIFICATE_NAME = '' # The name of the certificate stored in Key Vault

# Create a logging mechanism
def enable_logging():
    stdout_handler = logging.StreamHandler(sys.stdout)
    handlers = [stdout_handler]
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers = handlers
    )

def main():
    try:

        # Enable logging
        enable_logging()

	    # Setup some sample data
        sample_data = {
                "value1":"some value 1",
                "value2":"some value 2",
                "value3":"some value 3",
                "value4":"some value 4"
        }

        # Convert the dict to string, encode to bytes, and hash the data
        sample_data_hash = hashlib.sha512(json.dumps(sample_data).encode('UTF-8')).digest()

        # Obtain a credential from the system-assigned managed identity
        msi_credential = DefaultAzureCredential()

        # Get the key from Key Vault and setup a cryptography client
        key_client = KeyClient(KEY_VAULT_URL, msi_credential)
        key = key_client.get_key(CERTIFICATE_NAME)
        crypto_client = CryptographyClient(key, credential=msi_credential)

        # Use Key Vault to calculate a signature using RSASSA-PKCS1-v1_5 using SHA-512
        data_signature = (crypto_client.sign(SignatureAlgorithm.rs512,sample_data_hash)).signature
        
        # Retrieve the certificate from Key Vault
        cert_client = CertificateClient(KEY_VAULT_URL, msi_credential)
        result = (cert_client.get_certificate(CERTIFICATE_NAME)).cer
        
        # Load the DER certificate returned into an x509 object and get the public key
        cert= load_der_x509_certificate(result,backend=default_backend())
        public_key = cert.public_key()
        
        # Verify the signature
        try:
            public_key.verify(
                    signature=data_signature,
                    data=(json.dumps(sample_data)).encode('UTF-8'),
                    padding=padding.PKCS1v15(),
                    algorithm=hashes.SHA512()
            )
            logging.info('Payload verified successfully')
            print('Payload verified successfully!')

        except InvalidSignature:  
            print('Payload and/or signature files failed verification')

    except Exception:
        logging.error('Execution error: ', exc_info=True)

if __name__ == "__main__":
    main()