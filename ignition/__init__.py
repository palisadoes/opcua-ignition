"""Global variables for the various scripts."""

# Import packages
import getpass
import socket


HOSTNAME = "".join(_.upper() for _ in socket.gethostname() if _.isalnum())
USERNAME = "".join(_.upper() for _ in getpass.getuser() if _.isalnum())

SERVER_CERTIFICATE = "ignition-server.der"
CLIENT_PREFIX = "Ignition-OPCUA-Client-POC-Test"
CLIENT_APP_IDENTIFIER = f"{CLIENT_PREFIX}-{HOSTNAME}-{USERNAME}"
CLIENT_PRIVATE_KEY = f"{CLIENT_APP_IDENTIFIER}-key.pem"
CLIENT_CERTIFICATE = f"{CLIENT_APP_IDENTIFIER}-cert.der"
