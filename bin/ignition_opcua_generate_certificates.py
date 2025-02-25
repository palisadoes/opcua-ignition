#!/usr/bin/env python3
"""Script to generate certificates for polling Ignition OPCUA servers."""

import datetime
import argparse
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Repository Imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ignition import CLIENT_PRIVATE_KEY, CLIENT_CERTIFICATE


def generate_client_certs(args):
    """Generate client certificates.

    Args:
        args: CLI arguments

    Returns:
        None

    """
    # Initialize key variables
    file_certificate = f"{args.directory}{os.sep}{args.client_certificate}"
    file_private_key = f"{args.directory}{os.sep}{args.client_private_key}"
    failure = False

    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )

    # Create the certificate subject
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Santa Clara"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "example.org"),
            x509.NameAttribute(
                x509.NameOID.COMMON_NAME, "POC FreeOpcUa Client"
            ),
        ]
    )

    # Create the certificate
    date_time_now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(date_time_now)
        .not_valid_after(date_time_now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key, hashes.SHA256())
    )

    # Create private key file. No password [serialization.NoEncryption()]
    if os.path.isfile(file_private_key) is False:
        with open(file_private_key, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    else:
        failure = True
        print(
            f"""\
ERROR: File {file_private_key} already exists. This script will not alter it."""
        )

    # Create certificate file.
    if os.path.isfile(file_certificate) is False and failure is False:
        with open(file_certificate, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.DER))
    else:
        failure = True
        print(
            f"""\
ERROR: File {file_certificate} already exists. This script will not alter it."""
        )

    # Print success message
    if failure is False:
        print(f"Sucessfully generated certificate: {file_certificate}")
        print(f"Sucessfully generated private key: {file_private_key}")


def arguments():
    """Get the CLI arguments.

    Args:
        None

    Returns:
        args: NamedTuple of argument values


    """
    # Initialize key variables
    certs_location = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "..", "certs"
        )
    )

    # Create a parser
    parser = argparse.ArgumentParser(
        description="""\
Generates client certificates for polling Ignition OPCUA servers."""
    )

    # Add values to the parser object
    parser.add_argument(
        "-k",
        "--client_private_key",
        type=str,
        default=CLIENT_PRIVATE_KEY,
        help=f"""\
Name of the client's output private key. (Default: {CLIENT_PRIVATE_KEY}).""",
    )

    parser.add_argument(
        "-c",
        "--client_certificate",
        default=CLIENT_CERTIFICATE,
        type=str,
        help=f"""\
Name of the client's output certificate file. \
(Default: {CLIENT_CERTIFICATE})""",
    )

    parser.add_argument(
        "-d",
        "--directory",
        default=certs_location,
        type=str,
        help=f"""Certificate directory. (Default: {certs_location})""",
    )

    # Return
    args = parser.parse_args()
    return args


def main():
    """Generate certificates.

    Args:
        None

    Returns:
        None

    """
    # Get arguments
    args = arguments()

    # Generate certs
    generate_client_certs(args)


if __name__ == "__main__":
    main()
