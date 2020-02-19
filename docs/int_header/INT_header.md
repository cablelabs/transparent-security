# Transparent Security INT header reference definition

The INT header is an L4 wrapper containing in-band network telemetry.

These definitions contain modifications and required fields for Transparent Security.

  Note: This version of the document is still under discussion and may change.

This header heavily leverages the P4 INT header.  The changes and subset that are required for
Transparent Security noted in this document.

The draft of the 2.0 INT header document which we are using is located at [INT.pdf](https://github.com/cablelabs/transparent-security/wiki/attachments/INT.pdf).

## Overview

The INT header is defined in two portions.  One is the Header for the INT metadata and the second is the actual metadata.  For both of these, we follow the INT specification with a domain specific extension for the MAC address of the source device.

Please refer to the 2.0 draft or release version of the P4 Application for the metadata header format.  This document includes the definition of the domain specific extension and examples using a UDP header to encapsulate the packet.

## INT Header

### INT metadata header (12 bytes)

The hop-by-hop INT header will follow the header as described in section 4.7. INT Hop-by-Hop Metadata Header Format in the current INT specification.

* INT instructions are encoded as a bitmap in the 16 bit INT Instruction field.

  * bit0: 4 octet Switch ID which is unique across the network

### Per-Hop INT Metadata record (4 bytes)

The hop-by-hop metadata record will be updated at each hop on the network which supports the INT header.

Each metadata record corresponds to a bit field in the instruction set and is 4 octets long.  bit0 is the only required bit that needs to be set for transparent security, but other bits can be set as indicated by the INT specification.

* Bit0: Switch ID: Unique identifier for the switch (4 octets)

On the customer's gateway, the gateway enters its ID as the switch ID.

## Domain Specific Data

Transparent Security takes advantage of the domain specific extension to add source-only information to the INT header.

The Domain ID, DS Instruction bitmask and DS Flags size and location in the INT Metadata header are defined in the P4 INT specification.  The use of these fields is open to the definition by the use case.  This section of the document describes how these fields are used within Transparent Security.

### Domain ID

Domain ID for Transparent Security is 0x5453.  This is the ASCII values for TS.

### DS Instruction bitmask

* bit0: 8-byte source device ID
* The remaining bits are reserved

This source only information is an 8-byte source device ID.  This can be any device ID which is unique to the INT Domain.  This source ID can be the 6 byte MAC address of the source device followed by 2 bytes of 0x0000.

### DS Flags

The Domain Specific Flags are set as follows:

* bit 0 The source-only data was set by the source device
* bit 1 The source-only data was set by the gateway on the customer premises
* bit 2 The source-only data was set by a switch outside of the customer premises
* The remaining bits are reserved

Note: Only 1 of the first 3 bits can be set.  If more than 1 bit is set, then the DS flags are invalid.

It is valid to not set any of the bits if the architecture is not sure where it sits on the network with relation to the source device.  This could occur if the originating device is behind a secondary gateway.

### DS Metadata (8 bytes)

The domain specific metadata will contain source-only data.  This record will be populated when the INT header is initially inserted into the packet header.

This is a single 8-byte record with the source device ID.  This can be set on the source device or a gateway on the customer premises.

For example a source device's MAC address is "a6:1a:f6:b1:64:7d" the device ID would be 0xA61AF6B1647d0000.

It the DS metadata is set by a switch outside of the customer premises, this will likely identify the network device that forwarded the packet to the access network and not the actual device.

## Examples

### Example table for a device INT header

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
  <td height=42 class=xl65 style='height:32.0pt'>UDP Shim</td>
  <td colspan=4 class=xl63>Type = <font color="red">1</font></td>
  <td colspan=2 class=xl63>NPT = <font color="red">1</font></td>
  <td colspan=2 class=xl63>Res</td>
  <td colspan=8 class=xl63>Length = <font color="red">6</font></td>
  <td colspan=8 class=xl63>Reserved</td>
  <td colspan=8 class=xl63>Next Protocol</td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td rowspan=3 height=42 class=xl65 style='height:32.0pt'>INT-MD Metadata Header</td>
  <td colspan=4 class=xl63>Verstion = <font color="red">2</font></td>
  <td colspan=2 class=xl63>Res = <font color="red">0</font></td>
  <td>D = <font color="red">0</font></td>
  <td>E = <font color="red">0</font></td>
  <td>M = <font color="red">0</font></td>
  <td colspan=10 class=xl63>Reserved</td>
  <td colspan=5 class=xl63>Per-hop Metadata Length = <font color="red">1</font></td>
  <td colspan=8 class=xl63>Remaining Hop Cnt</td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=16 height=21 class=xl66 style='height:16.0pt'>Instruction Bitmap = <font color="red">1000000000000000</font></td>
  <td colspan=16 class=xl63>Domain Specific ID = <font color="red">0x5453</font></td>
 </tr>
<tr height=21 style='height:16.0pt'>
  <td colspan=16 height=21 class=xl66 style='height:16.0pt'>DS Instruction = <font color="red">1000000000000000</font></td>
  <td colspan=16 class=xl63>DS Flags = <font color="red">1000000000000000</font></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td rowspan=5 height=84 class=xl65 style='height:64.0pt'>INT Metadata</td>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Hop 3 Switch ID</td>
</tr>
<tr height=21 style='height:16.0pt'>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Hop 2 Switch ID
  <span style='mso-spacerun:yes'> </span></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Hop 1 Switch ID
  <span style='mso-spacerun:yes'> </span></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Originating Device
  MAC Most signifigant 4 octets<span style='mso-spacerun:yes'> </span></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=16 height=21 class=xl67 style='height:16.0pt'>Originating Device
  MAC least signifigant 2 octets</td>
  <td colspan=16 class=xl67>Reserved = <font color="red">0x0000</font></td>
 </tr>
</table>
