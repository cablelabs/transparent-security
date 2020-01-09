# Transparent Secuirty INT header reference definition

The INT header is an L3 wrapper containing in band network telemetry

## Overview

The INT header(s) will be inserted between the IP header and the datagram for IPv4 and will be a part of the extended header for IPv6.  The IP header will be updated to indicate that it has an INT header.

The INT header is defined in two portions.  One is the Header for the INT metadata and the second is the actual metadata.

There are two INT headers that will be used with Transparent Secuirty.  One for the origionating device on the customer premisis and the second is for the network path (Switches and gateways).

## IP Header update

### Encapsulation

We want to preserve the routing and other information on the packet, so we will modify the protocol (IPv4) / next header (IPv6), length and for IPv4 the header checksum.

Define a new L3 protocol.  The protocol for the INT INT header will be 63 "Any local network", since the INT header should never be exposed outside of the service providers network.  There is no specification for portocol 63.

IPv4:

* Update the total lenght to match the new size.
* Set the Protocol to the INT procol number. 253
* Update the header checksum

IPv6:

* Set the Next Header to be the identifier for an IPv6 extension header to the INT procol number.  If exisint extension headers are in place, INT will prepend to the first extension header.
* The INT header next header field will be the exisint IPv6 next header value.
* The Hdr Ext Len will be updated appropriatly

### Decapsulation

The origional protocol / next header will be restored and the size and checksum will be recalculated as appropriate.

## INT Header

### INT metadata header (64 bits)

This format will be used for both the device INT header and the network path INT header.  The INT instruction bitmask will indicat which data will be used.

* Each INT metadata header is 8B long and should be 0 when initialized
  * Ver (2b): INT metadata header version. Should be zero for this version
  * Rep (2b): Replication requested. Should be zero
  * C (1b): Copy. Should be zero
  * E (1b): Max Hop Count exceeded. Set to 1 for the device INT header and when the max hop count has been exceeded with the networking header.
  * Reserved (4b): Always zero.
* Instruction Count (5b): The number of instructions that are set (i.e., number of
1’s) in the instruction bitmap. This is 00010 (decimle 2) for the default gateway INT header.  Can be changed to add additional data.
* Max Hop Count (8b): 1 for the device INT header and configurable for the network header.
* Total Hop Count (8b): The current hop count for the network header and 1 for the device header.
* INT instructions are encoded as a bitmap in the 16 bit INT Instruction field: the first 8 bits
corresponds to a specific standard metadata as specified in Section 3 of the P4 INT spec.  The 9th-11th are defined in the metadata section below.  For the device ID the default is 000000001110000000.  If the originating device is using IPv6, then the originating IP address is not captured and the bit mask for the device INT header will be 000000001100000000.  For the network INT header the bit mask would be 100000000000000000.   Additional metadata can be added for the network INT header for performance and additional use cases.
  * bit0 (MSB): Switch ID
  * bit8: Origionating Device MAC (Most signifigant 4 octects)
  * bit9: Origionating Device MAC (Least signifigant 2 octects + 2 octects of 0 padding)
  * bit10: Origionating Device IPv4 address (4 octects)
* Next header IPv6 / Protocl IPv4 (1 octect)  If this is the last INT (header before the data gram), this will be the initial protocol from the IP header.  If there are subsequent headers then this will be 63 to denote that another INT header is to follow.
* Reservered (1 octects)

### Device INT Metadata (96 bits)

This section is deviating from the INT spec as we are removing the leading bit to indicate the last record.

This metadata will only containe one record and will not be updated on subsequent hops.

Each metadata record corrosponds to a bit filed in the instruction set and is 4 octects long.

* Origionating Device MAC Most signifigant 4 octects (4 octects)
* Origionating Device MAC least signifigant 2 octects + 2 octects of padding (4 octects)
* Origionating Device IPv4 (4 octects)

### Network INT Metadata (32 bits per hop)

This section is deviating from the INT spec as we are removing the leading bit to indicate the last record.

This metadat will be updated with each consecutive hop, until the max hop count has been reached.  The additional hop infomration will be inserted between the INT metadata header and the metadata from the previous hop.

Each metadata record corrosponds to a bit filed in the instruction set and is 4 octects long.

* Switch ID: Unique identfier for the swtich (4 octects)