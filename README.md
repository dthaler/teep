# TEEP

C Implementation of [draft-ietf-teep-protocol](https://tools.ietf.org/html/draft-ietf-teep-protocol/) and
[draft-ietf-teep-otrp-over-http](https://tools.ietf.org/html/draft-ietf-teep-otrp-over-http).

The directories are organized as follows.

Directories to make external libraries compile into static libs usable in a Trusted Application (TA),
with actual files under the directories of the same names under the external/ directory:

* ctoken: EAT implementation.

* LibEay32: OpenSSL's crypto library.

* openssl_includes: Copies OpenSSL includes into the openssl directory where other libs can find them.

* qcbor: CBOR implementation.

* t\_cose: COSE implementation.

Protocol:

* protocol/TeepAgentBrokerLib: TEEP Agent Broker in a static lib.

* protocol/TeepAgentLib: TEEP Agent in a static lib.

* protocol/TeepCommonLib: TEEP common static lib used by TeepAgentLib and TeepTamLib.

* protocol/TeepTamBrokerLib: TEEP TAM Broker in a static lib.

* protocol/TeepTamLib: TEEP TAM in a static lib.

* protocol/WindowsHttpClientLib: HTTP client module for Windows.

* protocol/WindowsHttpServerLib: HTTP server module for Windows.

TAs:

* ta/TeepAgentTABrokerLib: Static lib containing a TEEP Agent Broker for communicating with TeepAgentTA.

* ta/TeepAgentTA: TA containing a TEEP Agent.

* ta/TeepCommonTALib: Static lib with TEEP trusted code that is needed by both TeepAgentTA and TeepTamTA.

* ta/TeepTamTABrokerLib: Static lib containing a TEEP TAM Broker for communicating with TeepTamTA.

* ta/TeepTamTA: TA containing a TEEP TAM.

Configuration:

* tam/manifests: Repository of SUIT manifest files for Trusted Components. This
  directory is read by the TeepTamBrokerLib and used to populate the TAM's
  repository of manifests.  A sample SUIT manifest is included by default.
  The files must be named as `<UUID>.cbor` where UUID is the TA ID.
  The project at https://gitlab.arm.com/research/ietf-suit/suit-tool
  can be used to generate SUIT manifest files.

Apps:

* DeviceHost: Sample host app to run a TEEP Agent Broker.

* TamHost: Sample host app to run a TEEP TAM Broker.

* TeepUnitTest: Standalone unit tests to test the TEEP implementation.

## Prerequisites

You must git clone this repository recursively:

```
git clone --recurse-submodules https://github.com/dthaler/teep.git
```

You must have the following installed to compile and debug:
* [Visual Studio 2019 or 2022](https://visualstudio.microsoft.com/). Any edition, including the (free) Community edition is fine
* [Open Enclave Visual Studio Extension](https://marketplace.visualstudio.com/items?itemName=MS-TCPS.OpenEnclaveSDK-VSIX) v0.17 or later
and its [prerequisites](https://github.com/dthaler/openenclave/blob/master/docs/GettingStartedDocs/VisualStudioWindows.md)

The TAM is currently written to run on Windows, due to the HTTP layer.
However, the TeepAgentBrokerLib/HttpHelper.h API should already be
platform-agnostic and one could replace the Windows HttpHelper.cpp with 
a different implementation for other platforms.

You must also have OpenSSL 3.0.7 or later installed to %ProgramW6432%\OpenSSL.
You can do this either by running a pre-built installer such as the one from
https://www.softpedia.com/get/Programming/Components-Libraries/OpenSSL.shtml
or by building it yourself as follows:

* cd external\openssl
* mkdir _build
* perl ..\Configure VC-WIN64A
* perl configdata.pm --dump
* nmake
* nmake install

## Running the code

Compiling on Windows will result in generating DeviceHost.exe and TamHost.exe.

DeviceHost.exe is run as follows:

```
Usage: DeviceHost [-s] [-r <TA ID>] [-u <TA ID>] <TAM URI>
       where -s if present means to only simulate a TEE
             -r <TA ID> if present is a TA ID to request (38b08738-227d-4f6a-b1f0-b208bc02a781 if none specified)
             -u <TA ID> if present is a TA ID that is no longer needed by any normal app
             <TAM URI> is the default TAM URI to use
```

The `<TA ID>` to request ought to be one of the SUIT manifests configured
on the TAM as noted above in the description of the `manifests` directory.

TamHost.exe is run as follows, but must be run as Administrator in order to
register the URI to listen on:

```
Usage: TamHost [-s] <TAM URI>
       where -s if present means to only simulate a TEE
             <TAM URI> is the TAM URI to use, e.g., http://192.168.1.37:54321/TEEP

Currently the <TAM URI> must end in /TEEP
```

### Keys

Before the TAM and the TEEP Agent can fully communicate, they must be configured to trust each other.
The `trusted` directory under `tam` and `agent` contain a set of `.pem` files
of public keys that that entity considers trusted.

This can be done as follows:

* The first time that TamHost is run it will generate `tam-public-key.pem` and `tam-private-key-pair.pem`
  under the `tam` directory.
* The first time that DeviceHost is run it will generate `agent-public-key.pem` and `agent-private-key-pair.pem`
  under the `agent` directory.
* Copy `tam/tam-public-key.pem` to `agent/trusted/tam-public-key.pem`.
* Copy `agent/agent-public-key.pem` to `tam/trusted/agent-public-key.pem`.
* Restart the TamHost and DeviceHost.

## Configurations

The following configurations should work:

* DebugStandalone | x64 - Use this to test/run as a normal application
                outside any TEE, for development and debugging purposes.
* Debug | x64 - Use this to test/run on an SGX-capable machine
                or with the `-s` option to run on a non-SGX-capable machine
                but simulating run inside SGX.

To run and debug inside Visual Studio, change the debugger Working Directory
to $(OutDir).  To do this, right click on the project,
and change Properties -> Debugging -> Working Directory and change the
value to $(OutDir) instead of $(ProjectDir).  This is because the apps
will attempt to load the enclaves from the current directory.
