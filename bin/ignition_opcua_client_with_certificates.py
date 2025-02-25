#!/usr/bin/env python3
"""Script that polls Ignition OPCUA servers."""

# Standard imports
import argparse
import asyncio
import os
from pathlib import Path
import logging
import sys
import socket
from collections import namedtuple

# PIP imports
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.validator import (
    CertificateValidator,
    CertificateValidatorOptions,
)
from asyncua import ua
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Repository Imports
from ignition import (
    CLIENT_APP_IDENTIFIER,
    CLIENT_PRIVATE_KEY,
    CLIENT_CERTIFICATE,
    SERVER_CERTIFICATE,
)

# Setup logging
logging.basicConfig(level=logging.WARN)
_logger = logging.getLogger("asyncua")


async def main():
    """Poll OPCUA Server.

    Args:
        None

    Returns:
        None

    """
    # Get CLI arguments
    args = arguments()

    # Create an event loop
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(await poll(args))
    loop.close()


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


async def poll(args):
    """Poll the OPCUA server.

    Args:
        args: PollArgs object

    Returns:
        None


    """
    # Intialize key variables
    node_id = f"ns={args.namespace};{args.type}={args.node}"
    Certificate = namedtuple("Certificate", "name filename")
    file_client_certificate = (
        f"{args.directory}{os.sep}{args.client_certificate}"
    )
    file_client_private_key = (
        f"{args.directory}{os.sep}{args.client_private_key}"
    )
    file_server_certificate = (
        f"{args.directory}{os.sep}{args.ignition_server_certificate}"
    )
    url = f"""opc.tcp://\
{args.username}:{args.password}@{args.server}:{args.port}"""

    # Create a self signed certificate
    await setup_self_signed_certificate(
        Path(file_client_private_key),
        Path(file_client_certificate),
        CLIENT_APP_IDENTIFIER,
        socket.gethostname(),
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        {
            "countryName": "US",
            "stateOrProvinceName": "CA",
            "organizationName": "Self Signed Ignition Test POC",
        },
    )

    # Other stuff
    client_session = Client(url=url)
    client_session.application_uri = CLIENT_APP_IDENTIFIER
    await client_session.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=file_client_certificate,
        private_key=file_client_private_key,
        server_certificate=file_server_certificate,
    )

    # Create a certficate validator
    client_session.certificate_validator = CertificateValidator(
        CertificateValidatorOptions.EXT_VALIDATION
        | CertificateValidatorOptions.PEER_SERVER
    )

    # Print certificate fingerprints
    for item in [
        Certificate(
            name="Server Cert Signature:", filename=file_server_certificate
        ),
        Certificate(
            name="Client Cert Signature:", filename=file_client_certificate
        ),
    ]:
        fingerprint = get_certificate_fingerprint(item.filename)
        print(f"{item.name}\t {fingerprint}")

    # Print node_id value
    print(f"\nGetting NodeID: {node_id}\n")

    # Get data
    try:
        async with client_session:
            # Read tag
            root_node = client_session.get_root_node()
            print(root_node)
            root_node = client_session.get_objects_node()
            print(root_node)
            root_node = client_session.get_server_node()
            print(root_node)

            opcua_node = client_session.get_node(node_id).get_value()
            print(f"{opcua_node}: {await opcua_node.read_value()}")
    except ua.UaError as exp:
        _logger.error(exp)
        sys.exit(1)
    except asyncio.TimeoutError as exp:
        print(
            f"""\

*ERROR* This may be caused by the generated '{CLIENT_APP_IDENTIFIER}' \
certificate \
not being 'Trusted'. To rectify this, visit the OPCUA dashboard. Go to the \
'Config > Opcua > Security' menu and click on the 'Trust' button for \
'{CLIENT_APP_IDENTIFIER}.'"""
        )
        print(
            f"""\
Exception type: {type(exp)}, Exception message: {str(exp)}, \
Exception representation: {repr(exp)}
"""
        )
        sys.exit(1)
    except Exception as exp:
        print(
            f"""\
Exception type: {type(exp)}, Exception message: {str(exp)}, \
Exception representation: {repr(exp)}"""
        )
        sys.exit(1)


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
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"""\
About:
This script polls an 'Inductive Automation' Ignition OPCUA \
Server API configured to use certificate based authtentication.

Certificates:
1. A private key will first need to be generated and placed \
in the 'certs/' directory
2. You will need to download the server certificate to the \
'certs/' directory too.

Regenerating Server Certificates:
1) Whenever you regenerate the server certificate you will need to restart \
the Ignition OPCUA module.
2) Then you will need to install it in the 'certs/' directory for this \
script to use.
3) If the OPCUA module is not restarted you will get a \
"Reason='no certificate for provided thumbprint'" error.

Regenerating This Scripts Client Certificates:
1) This will need to be done whenever the client certificate expires
2) When this is done, you will need to delete the existing \
'{CLIENT_APP_IDENTIFIER}' certificate on the server and replace it with \
the newly generated one.
3) Client certificates created using the \
'ignition_opcua_generate_certificates.py' script.

Running the Script:
1) The first time the script is run, you will get a \
'BadSecurityChecksFailed' message.
2) This may be caused by the generated '{CLIENT_APP_IDENTIFIER}' \
certificate not being 'Trusted'.
3) To rectify this, visit the OPCUA dashboard. \
Go to the 'Config > Opcua > Security' menu and click on the \
'Trust' button for '{CLIENT_APP_IDENTIFIER}'.
""",
    )

    # Add values to the parser object
    parser.add_argument(
        "-s",
        "--server",
        required=True,
        type=str,
        help="""OPCUA server to poll.""",
    )

    parser.add_argument(
        "-p",
        "--port",
        default=62541,
        type=int,
        help="""OPCUA server port poll.""",
    )

    parser.add_argument(
        "-u",
        "--username",
        required=True,
        type=str,
        help="""OPCUA server password.""",
    )

    parser.add_argument(
        "-x",
        "--password",
        required=True,
        type=str,
        help="""OPCUA server username.""",
    )

    #########################################################################
    # Certificate related arguments
    #########################################################################

    parser.add_argument(
        "-k",
        "--client_private_key",
        type=str,
        default=CLIENT_PRIVATE_KEY,
        help=f"""\
Name of the client's private key file. (Default: {CLIENT_PRIVATE_KEY}).""",
    )

    parser.add_argument(
        "-c",
        "--client_certificate",
        default=CLIENT_CERTIFICATE,
        type=str,
        help=f"""\
Name of the client's certificate file. (Default: {CLIENT_CERTIFICATE})""",
    )

    parser.add_argument(
        "-i",
        "--ignition_server_certificate",
        default=SERVER_CERTIFICATE,
        type=str,
        help=f"""\
Name of the Ignition server's certificate file. (Default: \
{SERVER_CERTIFICATE})""",
    )

    parser.add_argument(
        "-d",
        "--directory",
        default=certs_location,
        type=str,
        help=f"""Certificate directory. (Default: {certs_location})""",
    )

    parser.add_argument(
        "-a",
        "--namespace",
        default=1,
        type=int,
        help="OPCUA Namespace. (Default: 1)",
    )

    parser.add_argument(
        "-t",
        "--type",
        default="s",
        type=str,
        help="""\
Type of OPCUA nodeID to poll. Options include \
[s=string, i=integer](Default: s)""",
    )

    parser.add_argument(
        "-n",
        "--node",
        type=str,
        help="OPCUA nodeID to poll",
    )

    # Return
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    asyncio.run(main())
