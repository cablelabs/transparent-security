# Transparent Security INT header reference definition

The INT header is an L3 wrapper containing in-band network telemetry.

These definitions contain modifications and required fields for Transparent Security.

  Note: This version of the document is still under discussion and may change.

This header heavily leverages the P4 INT header.  The changes and subset that are required for
Transparent Security noted in this document.

The current draft of the 2.0 INT header document is located at [INT.pdf](https://github.com/p4lang/p4-applications/blob/master/docs/INT.pdf)

## Overview

The INT IP shim header and the INT header(s) will be inserted after the IP header and before the datagram for IPv4 and will be a part of the extended header for IPv6.  The IP header will be updated to indicate that it has an INT header.

The INT header is defined in two portions.  One is the Header for the INT metadata and the second is the actual metadata.  For both of these, we follow the INT specification with the addition of two bitmasks.  This additional value, an 8 octet value for the originating device ID will be proposed to be added to the INT specification.

Please refer to the 2.0 draft or release version of the P4 Application for the metadata header format.  This document includes the definition of the additional metadata types for the originating device and a proposed IP shim.

The other shim types, including UDP/TCP, can also be used with the probe marker and not the differentiated service bit (DSCP), but those do not cover the range of IP traffic that is used in DDoS attacks.

## IP Header update

### Encapsulation

We want to preserve the routing and other information on the packet, so we will modify the protocol (IPv4) / next header (IPv6), length and IPv4 the header checksum.

Define a new L3 protocol.  The protocol for the INT header will be 63 "Any local network" since the INT header should never be exposed outside of the service providers network.  There is no specification for protocol 63.

IPv4:

* Update the total length to match the new size
* Set the protocol to the INT protocol number
* Update the header checksum

IPv6:

* Set the Next Header to be the identifier for an IPv6 extension header to the INT protocol number.  If existing extension headers are in place, INT will prepend to the first extension header
* The INT header next header field will be the existing IPv6 next header value
* The Hdr Ext Len will be updated appropriately

### IP header shim (4 bytes)

This shim shall be 4 bytes and include the original protocol (IPv4) or next protocol (IPv6) and the length of the INT metadata.

Type: (1 octet) This field indicates the type of INT Header following the shim header. Two Type values are used: one for the hop-by-hop header type and the other for the destination header type.

Reserved: (1 octet)

Length: (1 octet) This is the total length of INT metadata header, INT stack and the shim header in 4-byte words. A non-INT device may read this field and skip over INT headers.

Protocol: (1 octet) If IP protocol / next header is used to indicate INT, this field optionally stores the original protocol / next header value. Otherwise, this field is reserved.

### Decapsulation

The original protocol / next header will be restored and the size and checksum will be recalculated as appropriate.  The IP shim header and INT header are also removed.

## INT Header

### INT metadata header (12 bytes)

The hop-by-hop INT header will follow the header as described in section 4.7. INT Hop-by-Hop Metadata Header Format in the current INT specification.

* INT instructions are encoded as a bitmap in the 16 bit INT Instruction field and adds two new bits to include
the MAC address of the originating device:

  * Transparent Security the following bits:
  * bit0: 4 octet Switch ID which is unique across the network
  * bit8: Originating Device MAC (Most significant 4 octets)
  * bit9: Originating Device MAC (Least significant 2 octets + 2 octets of 0 padding)

### Per-Hop INT Metadata record (12 bytes)

This metadata will only contain one record and will not be updated on subsequent hops.

Each metadata record corresponds to a bit filed in the instruction set and is 4 octets long.

* Switch ID: Unique identifier for the switch (4 octets)
* Originating Device MAC Most significant 4 octets (4 octets)
* Originating Device MAC least significant 2 octets + 2 octets of reserved padding (4 octets)

On the customer's gateway, the gateway enters its ID as the switch ID and it inserts the originating devices MAC address.

If the INT header is created on a switch inside the head end.  This occurs when a header is not added at the customer premises.  Two entries are added, one for the gateway device.  In a DOCSIS network, this is the cable modem.

On subsequent hops where it isn't connected to the originating device or the originating device is not know, 0xFFFFFFFF will be inserted in the two "Originating Device MAC" records.

## Examples

### Example table for a device INT header

#### Hex example

00:02:01:01:  ver,rep,c,e=0 inst count=2 max_hop=1 curr_hop=1

00:C0:11:00: Bitmak with bits 8 & 9 set= 00:C0, Next protocol = UDP

00:0c:29:1c:ac:16 MAC address

:00:00: Reserved after MAC address

01:00:50:00:13:5e:b0: UDP Header for port 80

68:65:6c:6c:6f:20:77:6f:72:6c:64: "hello world" in hex

```bash
sudo mz ens33 -c 100 -B 172.16.98.1 -t ip "proto=253, p=\
00:02:01:01:\
00:C0:11:00:\
00:0c:29:1c:ac:16\
:00:00:\
01:00:50:00:13:5e:b0:\
68:65:6c:6c:6f:20:77:6f:72:6c:64\
, ttl=5"
```

#### HTML table

<table border=0 cellpadding=0 cellspacing=0 width=1419 style='border-collapse:
 collapse;table-layout:fixed;width:1056pt'>
 <col width=171 style='mso-width-source:userset;mso-width-alt:5461;width:128pt'>
 <col width=39 span=16 style='mso-width-source:userset;mso-width-alt:1237;
 width:29pt'>
 <col width=39 style='mso-width-source:userset;mso-width-alt:1237;width:29pt'>
 <col width=39 span=15 style='mso-width-source:userset;mso-width-alt:1237;
 width:29pt'>
 <tr height=21 style='height:16.0pt'>
  <td height=21 width=171 style='height:16.0pt;width:128pt'>Description</td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
  <td width=39 style='width:29pt'></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td height=21 style='height:16.0pt'>Octet</td>
  <td colspan=8 class=xl64>0</td>
  <td colspan=8 class=xl64>1</td>
  <td colspan=8 class=xl64>2</td>
  <td colspan=8 class=xl64>3</td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td height=21 style='height:16.0pt'>Bit</td>
  <td align=right>0</td>
  <td align=right>1</td>
  <td align=right>2</td>
  <td align=right>3</td>
  <td align=right>4</td>
  <td align=right>5</td>
  <td align=right>6</td>
  <td align=right>7</td>
  <td align=right>8</td>
  <td align=right>9</td>
  <td align=right>10</td>
  <td align=right>11</td>
  <td align=right>12</td>
  <td align=right>13</td>
  <td align=right>14</td>
  <td align=right>15</td>
  <td align=right>16</td>
  <td align=right>17</td>
  <td align=right>18</td>
  <td align=right>19</td>
  <td align=right>20</td>
  <td align=right>21</td>
  <td align=right>22</td>
  <td align=right>23</td>
  <td align=right>24</td>
  <td align=right>25</td>
  <td align=right>26</td>
  <td align=right>27</td>
  <td align=right>28</td>
  <td align=right>29</td>
  <td align=right>30</td>
  <td align=right>31</td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td height=42 class=xl65 style='height:32.0pt'>IP Shim</td>
  <td colspan=8 class=xl63>Type = <font color="red">1</font></td>
  <td colspan=8 class=xl63>Reserved</td>
  <td colspan=8 class=xl63>Length = <font color="red">6</font></td>
  <td colspan=8 class=xl63>Next Protocol</td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td rowspan=2 height=42 class=xl65 style='height:32.0pt'>Header</td>
  <td colspan=4 class=xl63>Verstion = <font color="red">2</font></td>
  <td colspan=2 class=xl63>Rep = <font color="red">0</font></td>
  <td>C = <font color="red">0</font></td>
  <td>E = <font color="red">0</font></td>
  <td>M = <font color="red">0</font></td>
  <td colspan=10 class=xl63>Reserved</td>
  <td colspan=5 class=xl63>Per-hop Metadata Length = <font color="red">3</font></td>
  <td colspan=8 class=xl63>Remaining Hop Cnt</td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=16 height=21 class=xl66 style='height:16.0pt'>Instruction Bitmap = <font color="red">1000000011000000</font></td>
  <td colspan=16 class=xl63>Reserved</td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td rowspan=3 height=84 class=xl65 style='height:64.0pt'>INT Metadata</td>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Switch ID</td>
</tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Originating Device
  MAC Most signifigant 4 octets<span style='mso-spacerun:yes'> </span></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=16 height=21 class=xl67 style='height:16.0pt'>Originating Device
  MAC least signifigant 2 octets</td>
  <td colspan=16 class=xl67>Reserved</td>
 </tr>
</table>
