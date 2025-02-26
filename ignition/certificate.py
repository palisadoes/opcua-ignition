"""Certificate Manager."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes


class Client:
    """Client Certificate Handler Class."""

    def __init__(self, filepath_cert, filepath_key):
        """Instantiate the class.

        Args:
            filepath_cert: Filepath to the certificate
            filepath_key: Filepath to the private key

        Returns:
            None
        """
        # Initialize key variables
        self.filepath_cert = filepath_cert
        self.filepath_key = filepath_key

    def certificate_signature(self, hash_algorithm=hashes.SHA1()):
        """Get the certificate signature.

        Args:
            filepath_cert: Filepath to the certificate

        Returns:
            None
        """
        # Return
        result = get_certificate_fingerprint(
            self.filepath_cert, hash_algorithm=hash_algorithm
        )
        return result


class Server:
    """Server Certificate Handler Class."""

    def __init__(self, filepath_cert):
        """Instantiate the class.

        Args:
            filepath_cert: Filepath to the certificate

        Returns:
            None
        """
        # Initialize key variables
        self.filepath_cert = filepath_cert

    def certificate_signature(self, hash_algorithm=hashes.SHA1()):
        """Get the certificate signature.

        Args:
            filepath_cert: Filepath to the certificate

        Returns:
            None
        """
        # Return
        result = get_certificate_fingerprint(
            self.filepath_cert, hash_algorithm=hash_algorithm
        )
        return result


def get_certificate_fingerprint(der_filepath, hash_algorithm=hashes.SHA1()):
    """
    Reads a DER-encoded certificate file and returns its fingerprint.

    Args:
        der_filepath (str): Path to the DER-encoded certificate file.
        hash_algorithm: The hash algorithm to use
            (e.g., hashes.SHA256(), hashes.SHA1(), hashes.MD5()).
            Defaults to SHA256.

    Returns:
        result: The hexadecimal representation of the certificate fingerprint.
    """
    # Initialize key variables
    result = None
    success = False

    # Read the file
    with open(der_filepath, "rb") as f:
        der_data = f.read()

    # Evaluate
    try:
        cert = x509.load_der_x509_certificate(der_data)
        success = True
    except Exception as e:
        print(f"An error occurred: {e}")

    # Return
    if bool(success) is True:
        fingerprint_bytes = cert.fingerprint(hash_algorithm)
        result = fingerprint_bytes.hex()
    return result
