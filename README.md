# OTrP

C Implementation of draft-ietf-teep-opentrustprotocol and 
https://tools.ietf.org/html/draft-thaler-teep-otrp-over-http

The directories are organized as follows.

External:

* jansson: Static lib implementation of JSON, ported to run in a TA.

* jose: Static lib implementation of JOSE, ported to run in a TA.

* jose_openssl: Static lib implementation of JOSE's use of OpenSSL crypto library, ported to run in a TA.

* LibEay32: Static lib implemenation of OpenSSL crypto library, ported to run in a TA.

Time:

* UntrustedTimeLib: Static lib untrusted app-side support for calling untrusted absolute time APIs from a TA.

* UntrustedTimeTALib: Static lib TA-side support for calling untrusted absolute time APIs from a TA.

OTrP:

* OTrPAgentBrokerLib: OTrP Agent Broker in a static lib.

* OTrPAgentTA: OTrP Agent in a TA.

* OTrPTamBrokerLib: OTrP TAM Broker in a static lib.

* OTrPTamTA: OTrP TAM in a TA.

* OTrPCommonTALib: OTrP trusted code that is needed by both an Agent and a TAM.

Sample:

* DeviceTest: Sample test app to run an OTrP Agent Broker.

* TamTest: Sample test app to run an OTrP TAM Broker.
