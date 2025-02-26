# opcua-ignition
Sample Python 3 Scripts for Interacting with Inductive Automation's Ignition OPCUA API Server

## Setup

These scripts work best running in a virtual environment.

```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
(.venv) $ 
```

Import the packages defined in the `requirements.txt` file.

```bash
$ pip3 install -r requirements.txt
```

## Contributing

1. The scripts are meant solely as a proof of concept as the information on how to create scripts for Ignition is scarce.
1. Feel free to update the scripts and add new ones by opening pull requests.
1. If you create issues, please be prepared to create the related pull requests. This repository is a best effort activity.

## Scripts

The scripts are easy to run. Here is some important information.

1. The scripts are located in the `bin/` and are expected to be run from the repository root.
1. All certificates and private keys are expected to be located in the `certs/` directory
    1. The `ignition_opcua_generate_certificates.py` generates its certificates in the `certs/` directory

The scripts are meant solely as a proof of concept    

### Certificate Generation

The `ignition_opcua_generate_certificates.py` script generates certificates for querying the Ignition OPCUA server.

```
usage: ignition_opcua_generate_certificates.py [-h] [-k CLIENT_PRIVATE_KEY] [-c CLIENT_CERTIFICATE] [-d DIRECTORY]

Generates client certificates for polling Ignition OPCUA servers.

options:
  -h, --help            show this help message and exit
  -k CLIENT_PRIVATE_KEY, --client_private_key CLIENT_PRIVATE_KEY
                        Name of the client's output private key. (Default: poc_test_ignition_client_key.pem).
  -c CLIENT_CERTIFICATE, --client_certificate CLIENT_CERTIFICATE
                        Name of the client's output certificate file. (Default: poc_test_ignition_client_cert.der)
  -d DIRECTORY, --directory DIRECTORY
                        Certificate directory. (Default: certs/)
```

### Querying the Ignition API

The `ignition_opcua_generate_certificates.py` script queies an Ignition OPCUA server pre-configured to accept certificate signed queries.

```
usage: ignition_opcua_client_with_certificates.py [-h] -s SERVER [-p PORT] -u USERNAME -x PASSWORD [-k CLIENT_PRIVATE_KEY] [-c CLIENT_CERTIFICATE]
                                                  [-i IGNITION_SERVER_CERTIFICATE] [-d DIRECTORY] [-a NAMESPACE] [-t TYPE] [-n NODE] [-l] [-q INTERVAL]
                                                  [-e COUNT]

About:
This script polls an 'Inductive Automation' Ignition OPCUA Server API configured to use certificate based authtentication.

Certificates:
1. A private key will first need to be generated and placed in the 'certs/' directory
2. You will need to download the server certificate to the 'certs/' directory too.

Regenerating Server Certificates:
1) Whenever you regenerate the server certificate you will need to restart the Ignition OPCUA module.
2) Then you will need to install it in the 'certs/' directory for this script to use.
3) If the OPCUA module is not restarted you will get a "Reason='no certificate for provided thumbprint'" error.

Regenerating This Scripts Client Certificates:
1) This will need to be done whenever the client certificate expires
2) When this is done, you will need to delete the existing 'Tag:Read:Test' certificate on the server and replace it with the newly generated one.
3) Client certificates created using the 'ignition_opcua_generate_certificates.py' script.

Running the Script:
1) The first time the script is run, you will get a 'BadSecurityChecksFailed' message.
2) This may be caused by the generated 'Tag:Read:Test' certificate not being 'Trusted'.
3) To rectify this, visit the OPCUA dashboard. Go to the 'Config > Opcua > Security' menu and click on the 'Trust' button for 'Tag:Read:Test'.

options:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        OPCUA server to poll.
  -p PORT, --port PORT  OPCUA server port poll.
  -u USERNAME, --username USERNAME
                        OPCUA server password.
  -x PASSWORD, --password PASSWORD
                        OPCUA server username.
  -k CLIENT_PRIVATE_KEY, --client_private_key CLIENT_PRIVATE_KEY
                        Name of the client's private key file. (Default: poc_test_ignition_client_key.pem).
  -c CLIENT_CERTIFICATE, --client_certificate CLIENT_CERTIFICATE
                        Name of the client's certificate file. (Default: poc_test_ignition_client_cert.der)
  -i IGNITION_SERVER_CERTIFICATE, --ignition_server_certificate IGNITION_SERVER_CERTIFICATE
                        Name of the Ignition server's certificate file. (Default: ignition-server.der)
  -d DIRECTORY, --directory DIRECTORY
                        Certificate directory. (Default: /home/peter/code/GitHub/palisadoes/opcua-ignition/certs)
  -a NAMESPACE, --namespace NAMESPACE
                        OPCUA Namespace. (Default: 1)
  -t TYPE, --type TYPE  Type of OPCUA nodeID to poll. Options include [s=string, i=integer](Default: s)
  -n NODE, --node NODE  OPCUA nodeID to poll
  -l, --loop            Repeatedly loop to get the data if True
  -q INTERVAL, --interval INTERVAL
                        Looping interval in seconds, if '--loop' is True
  -e COUNT, --count COUNT
                        Number of loops to perform.
```