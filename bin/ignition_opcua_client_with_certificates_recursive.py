#!/usr/bin/env python3
"""Script that recursively obtains OPCUA tags from an Ignition OPCUA server."""

# Standard imports
import argparse
import asyncio
import os
from pathlib import Path
import logging
import sys
import socket
import time
from pprint import pprint

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

# Repository Imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ignition import (
    CLIENT_APP_IDENTIFIER,
    CLIENT_PRIVATE_KEY,
    CLIENT_CERTIFICATE,
    SERVER_CERTIFICATE,
)

from ignition.certificate import Client as ClientCert
from ignition.certificate import Server as ServerCert

# Setup logging
logging.basicConfig(level=logging.WARN)
_logger = logging.getLogger("asyncua")


def main():
    """Poll OPCUA Server.

    Args:
        None

    Returns:
        None

    """
    # Get CLI arguments
    args = arguments()

    # Create the node ID
    node_id = f"ns={args.namespace};{args.type}={args.node}"

    # Print node_id value being polled
    print(f"\nGetting NodeID: {node_id}\n")

    # Create client certificate objects
    client_cert = ClientCert(
        f"{args.directory}{os.sep}{args.client_certificate}",
        f"{args.directory}{os.sep}{args.client_private_key}",
    )

    # Create client certificate objects
    server_cert = ServerCert(
        f"{args.directory}{os.sep}{args.ignition_server_certificate}"
    )

    # Print
    print(
        f"""\
Client Cert Fingerprint/Signature:\t {client_cert.certificate_signature()}
Server Cert Fingerprint/Signature:\t {server_cert.certificate_signature()}
"""
    )

    # Create the polling URL
    url = f"""opc.tcp://\
{args.username}:{args.password}@{args.server}:{args.port}"""

    # Create an event loop
    count = args.count if bool(args.loop) else 1
    for _ in range(count):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        task = loop.create_task(poll(node_id, url, client_cert, server_cert))
        loop.set_debug(True)
        loop.run_until_complete(task)
        loop.close()

        # Sleep
        if bool(args.loop):
            time.sleep(args.interval)


async def poll(node_id, url, client_cert, server_cert):
    """Poll the OPCUA server.

    Args:
        node_id: Node id to poll
        url: URL to poll
        client_cert: ignition.certificate.Client object
        server_cert: ignition.certificate.Server object

    Returns:
        None


    """
    # Create a self signed certificate
    await setup_self_signed_certificate(
        Path(client_cert.filepath_key),
        Path(client_cert.filepath_cert),
        CLIENT_APP_IDENTIFIER,
        socket.gethostname(),
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        {
            "countryName": "US",
            "stateOrProvinceName": "CA",
            "organizationName": "Self Signed Ignition Test POC",
        },
    )

    # Create the client session
    client_session = Client(url=url)

    # Apply the app identifier to the client
    client_session.application_uri = CLIENT_APP_IDENTIFIER

    # Apply the security certificates
    await client_session.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=client_cert.filepath_cert,
        private_key=client_cert.filepath_key,
        server_certificate=server_cert.filepath_cert,
    )

    # Create a certficate validator
    client_session.certificate_validator = CertificateValidator(
        CertificateValidatorOptions.EXT_VALIDATION
        | CertificateValidatorOptions.PEER_SERVER
    )

    # Get data
    try:
        async with client_session:
            # Read root
            print(
                "Root children are",
                await client_session.nodes.root.get_children(),
            )

            # Read tag
            opcua_node = client_session.get_node(node_id)

            print(dir(opcua_node))

            print(f"\n\n\n{node_id}\n\n\n\n")

            print(
                f"""\
            Node: {opcua_node} -> children: {await opcua_node.get_children()}\n"""
            )

            # tag_list = dict()
            # variables = await opcua_node.get_variables()
            # for i in variables:
            #     tag_list[i.nodeid.Identifier] = i
            # pprint(tag_list)

            # print(f"Node: {opcua_node} -> variables: {variables}\n")

            print(
                f"""\
    Node: {opcua_node} -> Value: {await opcua_node.get_value()}\n"""
            )
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
in the 'certs/' directory using the \
ignition_opcua_generate_certificates.py script.
2. You will need to download the server certificate to the \
'certs/' directory too.

Regenerating Server Certificates:
1. Whenever you regenerate the server certificate you will need to restart \
the Ignition OPCUA module.
2. Then you will need to install it in the 'certs/' directory for this \
script to use.
3. If the OPCUA module is not restarted you will get a \
"Reason='no certificate for provided thumbprint'" error.

Regenerating This Scripts Client Certificates:
1. This will need to be done whenever the client certificate expires
2. When this is done, you will need to delete the existing \
'{CLIENT_APP_IDENTIFIER}' certificate on the server and replace it with \
the newly generated one.
3. Client certificates created using the \
'ignition_opcua_generate_certificates.py' script.

Running the Script:
1. The first time the script is run, you will get a \
'BadSecurityChecksFailed' message.
2. This may be caused by the generated '{CLIENT_APP_IDENTIFIER}' \
certificate not being 'Trusted'.
3. To rectify this, visit the OPCUA dashboard. \
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

    parser.add_argument(
        "-l",
        "--loop",
        action="store_true",
        help="Repeatedly loop to get the data if True",
    )

    parser.add_argument(
        "-q",
        "--interval",
        default=5,
        help="Looping interval in seconds, if '--loop' is True",
    )

    parser.add_argument(
        "-e",
        "--count",
        default=10,
        help="Number of loops to perform.",
    )

    # Return
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    main()
