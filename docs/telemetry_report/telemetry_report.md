# Telemetry Report
The telemetry report is the packet format for sending INT and standard header
data to an analytics engine for identifying attacks. This will leverage the
following specification from the P4 Organization,
[2.0 release of the telemetry report](https://github.com/p4lang/p4-applications/blob/master/telemetry/specs/telemetry_report.mdk).

## Transparent Security Telemetry Report Usage
Switches will generate two categories of Telemetry Reports for Transparent
Security. Tracked flows will be used to sample the forwarded traffic and drop
reports will be using determine if an attack is being mitigated.

### Tracked Flows
The sampled reports will be categorized as "Tracked Flows" in section 2.2 of
the specification. These will only be generated by the sink switches that will
typically be core switches or edge routers. The tracked flows reports will be
used to identify when an attack beings and its source and will generate reports
in the INT-MD (eMbed Data) mode as defined in section 2.4.2 of the
specification.

### Drop Reports
Drop reports will be generated by all devices which are mitigating the attack.
This can be used to track the effectiveness of the mitigation and when the
attack has stopped.

## Sampling rate
The sampling rate is configurable per deployment. It can range from every
packet to 1 per thousands depending on the load and granularity.

## Information form original packet included in TR
A packet fragment including all original packet headers, INT data and the
truncated payload where the total number of bytes of the Telemetry Report shall
not exceed the configured number of bytes (reference implementation currently
set at 200). The size of the packet fragment can configurable per deployment
and may vary based the the packet type (i.e IPv4, IPv6).

### UDP header
The report will use the UDP outer encapsulation as specified in section 3.1 of
the report. To simplify the processing, this MUST be a different port than is
used by the INT header and will be configurable per deployment. For PoCs we
will use UDP port 8555. The UDP source port will be set to 0, since the flows
are being tracked on the analytics engine and not on the switches.

### Telemetry Report Header
The Domain Specific ID will be set to 0x5453, which is the same Domain Specific
ID used for the INT header for Transparent Security. This will enable multiple
types of telemetry reports to co-exist in the same network domain.

The Domain Specific Md Bits and Status are not being used and are reserved. Set
them to 0x0000 and 0x0000.

### Notes from the current state of the 2.0 telemetry report
The 2.0 Telemetry Report is still being completed.

Based input from this project, we have initial agreement to enable multiple
reports to be collated in a single packet.  The current draft of this change is
listed below:

There are two high level options for the packet structure, both will be
specified in Telemetry Report v2.0:
The more compact format uses an "InnerProtocol" field to identify whether a
packet fragment or domain specific extensions are included in the report. In
order to get to those fields, the receiver of the report has to parse through
variable optional metadata based on RepMdBits and Domain Specific Md Bits. If
it does not understand how to parse those bits, then it cannot figure out where
the packet fragment or domain specific extensions begin. This format adds only
4 bytes, compared to the Telemetry Report v1.0 format.

Nested TLV structure. An implementation that does not support coalescing needs
to generate two levels of TLVs, each with only one TLV, with two different
lengths values. This format adds 8 bytes compared to the Telemetry Report v1.0
format.

#### Compact Telemetry Report Header v2.0
```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |   hw_id   |              Sequence Number              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Node id                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   --
|RepType|InType | Report Length |   MD Length   |D|Q|F|I| Rsvd  |   /\
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ||
|           RepMdBits           |      Domain Specific ID       |   ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ||
|           DsMdBits            |          DsMdStatus           | Report
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ||
|            Variable Option Baseline & DS Metadata             |   ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ||
|     Packet Fragment with INT data and portion of payload      |   \/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   --
```

#### Notes:
* The Sequence Number has been reduced from 32 bits to 22 bits in order to save
4 bytes.
* Length of each report is limited to 1024 bytes.
* The total length of the Telemetry Report packet should not have to exceed 200
bytes which is enough where the INT and original UDP/TCP data will not be lost
when the Telemetry Report and originating packet are both IPv6.

Inner Types:
- 0: None
- 1: TLV
- 2: Domain Specific Extensions
- 3: Ethernet Packet Fragment
- 4: IPv4 Packet Fragment
- 5: IPv6 Packet Fragment

#### Nested TLV Telemetry Report v2.0 proposal:
```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |   hw_id   |              Sequence Number              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Node id                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|RepType|InType | Report Length |   MD Length   |D|Q|F|I| Rsvd  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   --     --
|           RepMdBits           |      Domain Specific ID       |   /\     /\
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ||     ||
|           DsMdBits            |          DsMdStatus           |   ||     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Header   ||
|               Variable Optional RepMdBits Data                |   ||     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ||     ||
|               Variable Optional DSMdBits Data                 |   \/     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   —-     ||
|0 0 0 0| Rsvd  |  TLVLength    |       TLV Data Template       |   /\     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Rpt1  Report
|     Packet Fragment with INT data and portion of payload      |   \/     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   —-     ||
|0 0 0 0| Rsvd  |  TLVLength    |       TLV Data Template       |   /\     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Rpt2    ||
|     Packet Fragment with INT data and portion of payload      |   \/     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   —-     ||
|0 0 0 0| Rsvd  |  TLVLength    |       TLV Data Template       |   /\     ||
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Rpt n   ||
|     Packet Fragment with INT data and portion of payload      |   \/     \/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   --     --
```

### Notes:
* The Sequence Number has been reduced from 32 bits to 22 bits in order to save 4
bytes.
* Ingress Timestamp gets a RepMdBit value and moves into Variable Optional
Metadata.
* Length of each report is limited to 1024 bytes. If we want to expand that to
16k, then DQFI would have to move down, squeezing RepMdBits and Domain Specific
Md Bits to 28 bits, and either burn a separate type for each packet fragment
protocol, or move Protocol to the 16 Reserved bits on the right.
