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
