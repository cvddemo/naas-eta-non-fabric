Introduction
============
The rapid rise in encrypted traffic is changing the threat landscape. As
more businesses become digital, a significant number of services and
applications are using encryption as the primary method of securing
information. More specifically, encrypted traffic has increased by more
than 90 percent annually, with more than 40 percent of web sites
encrypting traffic in 2016 versus 21 percent in 2015.

Encryption technology has enabled much greater privacy and security for
enterprises and individuals that use the Internet to communicate and
transact business online. Mobile, cloud and web applications rely on
well-implemented encryption mechanisms that use keys and certificates to
ensure security and trust. However, businesses are not the only ones to
benefit from encryption. Threat actors have leveraged these same
benefits to evade detection and to secure their malicious activities.

Traditional flow monitoring, as implemented in the Cisco® Network as a
Sensor (NaaS) solution and through the use of NetFlow, provides a
high-level view of network communications by reporting the addresses,
ports, and byte and packet counts of a flow. In addition, *intraflow
metadata*, or information about events that occur inside of a flow, can
be collected, stored, and analyzed within a flow monitoring framework.
This data is especially valuable when traffic is encrypted, because
deep-packet inspection is no longer viable. This intraflow metadata,
called *Encrypted Traffic Analytics* (ETA), is derived by using new data
elements or telemetry that are independent of protocol details, such as
the lengths and arrival times of packets within a flow. These data
elements have the property of applying equally well to both encrypted
and unencrypted flows.

ETA focuses on identifying malware communications in encrypted traffic
through passive monitoring, the extraction of relevant data elements,
and supervised machine learning with cloud based global visibility.

ETA extracts three main data elements: the initial data packet, the
sequence of packet length and times, and TLS-specific features.

.. note::

    For more information about Encrypted Traffic Analytics, see the complete `ETA
Whitepaper <https://www.cisco.com/c/dam/en/us/solutions/collateral/enterprise-networks/enterprise-network-security/nb-09-encrytd-traf-anlytcs-wp-cte-en.pdf>`__.

`Link text <http://example.com/>`_ 

Design Overview
============
This guide describes how to enable NaaS with ETA, providing both
cryptographic assessment of the cipher suites used for TLS encrypted
communications as well as the ability to identify malicious traffic
patterns with the encrypted traffic of users in both campus and branch
networks. This CVD discusses the use of Cisco Stealthwatch version 6.9.2
when integrated with Cisco Cognitive Threat Analytics (CTA) in passively
monitoring encrypted endpoint and server traffic traversing Cisco
Catalyst 9300/9400 series switches or IOS-XE based routers, such as the
Cisco ASR 1000,ISR 4000, ISRv, and CSR 1000v supporting ETA and Flexible
NetFlow (FNF).

Cisco NaaS provides deeper visibility into the network by leveraging
Flexible NetFlow on switches, routers and wireless LAN controllers
(WLCs). When leveraging Cisco Identity Services Engine (ISE), pxGrid,
TrustSec, and Cisco Stealthwatch, NaaS can additionally quarantine
attacks.

With the release of Cisco IOS-XE 16.6.2 for Catalyst 9300/9400 switches
and the ASR1K/ISR4K/ISRv/CSR, the NaaS Solution deployed with
Stealthwatch 6.9.2 and integrated with Cognitive Threat Analytics is now
extended, through the introduction of Encrypted Traffic Analytics, to
include the ability to conduct cryptographic assessment or crypto audit
as well as malware detection of TLS or SSL encrypted traffic.

.. note::

As of IOS-XE 16.6.2, the Cisco 1100 router also supports ETA; however, it was not tested for inclusion in this CVD.

#. Flexible NetFlow and ETA

Although it is possible to just configure ETA, it is necessary to also
configure FNF for analysis of encrypted traffic in the Cognitive Threat
Analytics cloud for malware detection as ETA only sends information
about the IDP and SPLT collected and processed by the switch. For full
NetFlow statistics containing connection and peer information such as
number of bytes, packet rates, round trip times, and so on, you must
also configure FNF. For the singular purpose of performing a crypto
audit, however, it is only necessary to enable ETA on the switch.

The following tables depicting the IDP and SPLT templates list those
NetFlow key and non-key fields included in the exported record when ETA
is enabled. As you can see, this is a small subset of the data elements
that can be collected via FNF and thus the reason for configuring both
ETA and FNF.

Table 1 IDP template

+---------------------------------+-----------------+-------------------------+
| **Information element**         | **Flow key?**   | **NetFlow V9 length**   |
+=================================+=================+=========================+
| sourceIPv4Address               | Y               | 4                       |
|                                 |                 |                         |
| (sourceIPv6Address)             |                 | (16)                    |
+---------------------------------+-----------------+-------------------------+
| destinationIPv4Address          | Y               | 4                       |
|                                 |                 |                         |
| (destinationIPv6Address)        |                 | (16)                    |
+---------------------------------+-----------------+-------------------------+
| sourceTransportPort             | Y               | 2                       |
+---------------------------------+-----------------+-------------------------+
| destinationTransportPort        | Y               | 2                       |
+---------------------------------+-----------------+-------------------------+
| protocolIdentifier              | Y               | 1                       |
+---------------------------------+-----------------+-------------------------+
| flowStartSysUpTime              | N               | 4                       |
+---------------------------------+-----------------+-------------------------+
| flowEndSysUpTime                | N               | 4                       |
+---------------------------------+-----------------+-------------------------+
| packetDeltaCount                | N               | 8                       |
+---------------------------------+-----------------+-------------------------+
| octetDeltaCount                 | N               | 8                       |
+---------------------------------+-----------------+-------------------------+
| initialDataPacket (v9), or      | N               | 1300                    |
|                                 |                 |                         |
| ipHeaderPacketSection (IPFIX)   |                 |                         |
+---------------------------------+-----------------+-------------------------+

Table 2 SPLT template

+-----------------------------------------------+-----------------+-------------------------+
| **Information element**                       | **Flow key?**   | **NetFlow V9 length**   |
+===============================================+=================+=========================+
| sourceIPv4Address                             | Y               | 4                       |
|                                               |                 |                         |
| (sourceIPv6Address)                           |                 | (16)                    |
+-----------------------------------------------+-----------------+-------------------------+
| destinationIPv4Address                        | Y               | 4                       |
|                                               |                 |                         |
| (destinationIPv6Address)                      |                 | (16)                    |
+-----------------------------------------------+-----------------+-------------------------+
| sourceTransportPort                           | Y               | 2                       |
+-----------------------------------------------+-----------------+-------------------------+
| destinationTransportPort                      | Y               | 2                       |
+-----------------------------------------------+-----------------+-------------------------+
| protocolIdentifier                            | Y               | 1                       |
+-----------------------------------------------+-----------------+-------------------------+
| flowStartSysUpTime                            | N               | 4                       |
+-----------------------------------------------+-----------------+-------------------------+
| flowEndSysUpTime                              | N               | 4                       |
+-----------------------------------------------+-----------------+-------------------------+
| packetDeltaCount                              | N               | 8                       |
+-----------------------------------------------+-----------------+-------------------------+
| octetDeltaCount                               | N               | 8                       |
+-----------------------------------------------+-----------------+-------------------------+
| Sequence of Packet Lengths and Times (SPLT)   | N               | 40                      |
+-----------------------------------------------+-----------------+-------------------------+

.. Reader Tip::

    A complete list of the unique data elements provided in ETA records can be found in Appendix A

Crypto Audit
************

*Crypto audit* is the capability of viewing/reporting and eventually
alerting and alarming on the crypto fields in the Stealthwatch database.
The crypto audit functionality provides detailed information about the
cipher suites used for TLS communications, including the encryption
version, key exchange, key length, cipher suite, authentication
algorithm, and hash used.

With the crypto audit functionality enabled by ETA, the unencrypted
metadata in the Client Hello and Client Key Exchange messages provides
information that can be used to make inferences about the client's
Transport Layer Security (TLS) library and the cipher suites used. The
collection of this information begins with the *initial data packet*
(IDP), or first packet of the flow, and continues through subsequent
messages comprising the TLS handshake. This data is then exported by the
device via NetFlow and collected at the Stealthwatch Flow Collector
(FC). Once collected, these records can be queried by Stealthwatch
Management Console (SMC) for analysis.

These flow records can be collected by a Stealthwatch Flow Collector
over a period of time and subsequently filtered, searched through, and
reported on at the Stealthwatch Management Console for auditing purposes
ensuring that the most secure cipher suites are used to secure
confidential information as well as providing evidence of regulatory
compliance.

Malware Detection
************
When implementing ETA, in addition to cryptographic assessment, the
metadata collected can also be used to detect malware within the
encrypted traffic without the need to decrypt the traffic when Cisco
Stealthwatch is integrated with Cognitive Threat Analytics. When
combining Flexible NetFlow and DNS information along with the ETA
metadata found in the IDP, other ETA data elements such as Sequence of
Packet Length and Times (SPLT) provide a unique and valuable means for
identifying malware through the detection of suspicious traffic.

SPLT telemetry is composed of a set of two parameters describing each of
the first 10 packets of a flow—the length of the application payload in
that packet and the inter-arrival time from the previous packet. Only
packets that carry some application payload are considered; the rest
(such as SYN or SYN/ACK) are ignored. The SPLT provides visibility
beyond the first packet of the encrypted flows. The analysis of the
metadata contained in the IDP and SPLT greatly enhance the accuracy of
malware detection in the Cognitive Threat Analytics cloud.

Although all endpoint traffic is monitored and records exported to the
Stealthwatch Flow Collectors, by default, only traffic crossing the
enterprise network perimeter (i.e., Internet-bound) and outside of the
enterprise address space as well as all DNS queries regardless of
domain, are sent by the Stealthwatch flow collector to the CTA cloud for
further analysis. All communications between the flow collector and the
CTA cloud as well as from the CTA cloud to the SMC is sent in an
encrypted TLS tunnel as seen below.

Figure 1. ETA malware detection in Cognitive Threat Analytics cloud

|image0|\ **7128F**

ETA and FNF records for TLS-encrypted endpoint traffic destined
internally to other endpoints or servers within the organization's
internal address space are not sent to the Cognitive Threat Analytics
cloud for further inspection. However, with the combined ETA and FNF
records, cryptographic assessment can still be performed on these flows.

... Tech Tip::

    The enterprise address space (as identified by internal IP addresses or **Inside Hosts** as defined in Stealthwatch) are administered through the Host Groups settings within the SMC. By default, a Catch All host group is defined and consists of the RFC1918 address space. For more
    information, see "Deployment," later in this document.

After integration of Stealthwatch and CTA, FNF and ETA fields are
immediately sent to the CTA cloud for analysis. Initially, there will be
a brief "training" period in which analysis results may not be displayed
at the SMC. This is completely normal.
