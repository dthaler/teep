# TEEP

C Implementation of draft-ietf-teep-opentrustprotocol and 
https://tools.ietf.org/html/draft-thaler-teep-otrp-over-http

The directories are organized as follows.

External:

* jansson: Static lib implementation of JSON, ported to run in a TA.

* jose: Static lib implementation of JOSE, ported to run in a TA.

* jose_openssl: Static lib implementation of JOSE's use of OpenSSL crypto library, ported to run in a TA.

* LibEay32: Static lib implementation of OpenSSL crypto library, ported to run in a TA.

Time:

* UntrustedTimeLib: Static lib untrusted app-side support for calling untrusted absolute time APIs from a TA.

* UntrustedTimeTALib: Static lib TA-side support for calling untrusted absolute time APIs from a TA.

TEEP:

* TeepAgentBrokerLib: TEEP Agent Broker in a static lib.

* TeepAgentTA: TEEP Agent in a TA.

* TeepTamBrokerLib: TEEP TAM Broker in a static lib.

* TeepTamTA: TEEP TAM in a TA.

* TeepCommonTALib: TEEP trusted code that is needed by both an Agent and a TAM.

Sample:

* DeviceHost: Sample host app to run an TEEP Agent Broker.

* TamHost: Sample host app to run an TEEP TAM Broker.

## Prerequisites

You must have the following installed to compile and debug:

* [Visual Studio 2017](https://visualstudio.microsoft.com/vs/older-downloads/) (VS 2019 can compile but not debug, due to the current dependency on the Intel SGX SDK)
** Any edition, including the (free) Community edition is fine
* [Intel SGX SDK](https://software.intel.com/en-us/sgx/sdk) (currently required if creating code to run in SGX)

The TAM is currently written to run on Windows.

## Running the code

Compiling on Windows will result in generating DeviceHost.exe and TamHost.exe.

TamHost.exe represents the TAM and can be run without any command-line arguments, but must be run as Administrator.
Currently the TEEP URI to listen on is hard coded in TeepTamBrokerLib/HttpServer.h.
TODO: This needs to change to allow the IP address and port number to be specified on the command line,
and default to an IP address of the local machine, and some fixed port number (like 54321).

DeviceHost.exe is run as follows:

> DeviceHost <TAM URI> \[<TA ID>\]

where <TAM URI> is the default TAM URI to use, and <TA ID> is the TA to request
