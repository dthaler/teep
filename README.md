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

You must git clone this repository recursively:

```
git clone --recurse-submodules https://github.com/dthaler/OTrP.git
```

You must have the following installed to compile and debug:
* [Visual Studio 2019](https://visualstudio.microsoft.com/). Any edition, including the (free) Community edition is fine
* [Open Enclave Visual Studio Extension v0.7.29 or later](https://1drv.ms/u/s!Aqj-Bj9PNivcnvAKGa6fr8AlGk_a0g?e=am23nd) and its [prerequisites](https://github.com/dthaler/openenclave/blob/feature.vsextension/docs/GettingStartedDocs/VisualStudioWindows.md)

The TAM is currently written to run on Windows, due to the HTTP layer.
However, the TeepAgentBrokerLib/HttpHelper.h API should already be
platform-agnostic and one could replace the Windows HttpHelper.cpp with 
a different implementation for other platforms.

## Running the code

Compiling on Windows will result in generating DeviceHost.exe and TamHost.exe.

TamHost.exe represents the TAM and can be run without any command-line arguments, but must be run as Administrator.

DeviceHost.exe is run as follows:

```
Usage: DeviceHost <TAM URI> [<TA ID>]
        where <TAM URI> is the default TAM URI to use
        <TA ID> is the TA to request ("X" if none specified)
```

TamHost.exe is run as follows:

```
Usage: TamHost <TAM URI>
        where <TAM URI> is the TAM URI to use, e.g., http://192.168.1.37:54321/TEEP
        Currently the <TAM URI> must end in /TEEP
```

## Configurations

The following configurations should work:

* Debug | x64 - use this to test/run on an SGX-capable development machine

To run and debug inside Visual Studio, change the debugger Working Directory
to $(OutDir).  To do this, right click on the project,
and change Properties -> Debugging -> Working Directory and change the
value to $(OutDir) instead of $(ProjectDir).  This is because the apps
will attempt to load the enclaves from the current directory.
