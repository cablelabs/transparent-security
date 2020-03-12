# Telemetry Report

The telemetry report is the packet format for sending INT and standard header data to the analytics engine for identifying attacks.

This will leverage the Draft 2.0 release of the telemetry report.  This latest pull request for this is at [Telemetry Report 2.0 PR](https://github.com/p4lang/p4-applications/pull/61)

A PDF of a 2.0 telemetry report is available here: [Telemetry Report 2.0 draft PDF](https://github.com/cablelabs/transparent-security/wiki/attachments/telemetry_report.pdf)

## Transparent Security usage

These reports will of a type categorized as "Tracked Flows" in section 2.2 of the specification.

The architecture will generate reports in the INT-MD (eMbed Data) mode as defined in section 2.4.2 of the specification.

The sink switch, which is also known as the core or edge switch, is the egress switch with removes the INT header from the packet and generates the telemetry report.  It is not required for this switch to add it's INT data to the INT Metadata header, since it is also included in the telemetry report header.

## Sampling rate

The sampling rate is configurable per deployment.  It can range from every packet to 1 per thousands, depending on the load and granularity.

## Information form original packet included in TR

TR Ethernet
TR IP
TR UDP
TR Header

IP header
INT UDP header
INT UDP Shim
INT Header
INT Metadata
x bytes of data following the metadata.  This includes the L4 (i.e. UDP, TCP) and higher level headers from the source packet, but not the entire payload.

The number of bytes can configurable per deployment and may vary based the the packet type (i.e IPv4, IPv6).



### UDP header

The report will use the UDP outer encapsulation as specified in section 3.1 of the report.  To simplifying the processing, this MUST be a different port than is used by the INT header and will be configurable per deployment.  For PoCs we will use UDP port 8555.

The UDP source port will be set to 0, since the flows are being tracked on the analytics engine and not on the switches.

### Telemetry Report Header

THe Domain Specific ID will be set to 0x5453, which is the same Domain Specific ID used for the INT header for Transparent Security.  This will enable multiple types of telemetry reports to co-exist in the same network domain.

The Domain Specific Md Bits and Status are not being used and are reserved.  Set them to 0x0000 and 0x0000.

### Drop report

To track if a rule is still active, switches that are mitgating 

### Changes to telemetry report specification

Support multiple packets per report.  Use the length of the INT report header to find the next record.

For figure 6 should use the INT_TBD port and not the DSCP bit.  Should create a new image with the UDP encapsulation.
