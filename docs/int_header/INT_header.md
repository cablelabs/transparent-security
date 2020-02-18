# Transparent Security INT header reference definition

The INT header is an L4 wrapper containing in-band network telemetry.

These definitions contain modifications and required fields for Transparent Security.

  Note: This version of the document is still under discussion and may change.

This header heavily leverages the P4 INT header.  The changes and subset that are required for
Transparent Security noted in this document.

The draft of the 2.0 INT header document which we are using is located at [INT.pdf](https://github.com/cablelabs/transparent-security/wiki/attachments/INT.pdf).

## Overview

The INT header is defined in two portions.  One is the Header for the INT metadata and the second is the actual metadata.  For both of these, we follow the INT specification with a domain specific extension for the MAC address of the source device.

Please refer to the 2.0 draft or release version of the P4 Application for the metadata header format.  This document includes the definition of the domain specific extension and examples using a TCP/UDP header to encapsualte the packet.

## INT Header

### INT metadata header (12 bytes)

The hop-by-hop INT header will follow the header as described in section 4.7. INT Hop-by-Hop Metadata Header Format in the current INT specification.

* INT instructions are encoded as a bitmap in the 16 bit INT Instruction field.

  * bit0: 4 octet Switch ID which is unique across the network

### Per-Hop INT Metadata record (12 bytes)

This metadata will only contain one record and will not be updated on subsequent hops.

Each metadata record corresponds to a bit filed in the instruction set and is 4 octets long.  Only bit0 is required to be set for transparent secuirty, but other bits can be set as indicatied by the INT specifiction.

* Bit0: Switch ID: Unique identifier for the switch (4 octets)

On the customer's gateway, the gateway enters its ID as the switch ID and it inserts the originating devices MAC address.

If the INT header is created on a switch inside the head end.  This occurs when a header is not added at the customer premises.  Two entries are added, one for the gateway device.  In a DOCSIS network, this is the cable modem.

## Domain Specific Data

Transparent Secuirty takes advantage of the domain specific extension to add source-only infomraiton to the INT header.

For example a source device's MAC address is "a6:1a:f6:b1:64:7d" the device ID would be 0xA61AF6B1647dFF.

### Domain ID

Domain ID is 0x5453

### DS Instruction bit mask

* bit0: 8 byte source device ID
* The remaining bits are reserved

This source only information is a 8 byte source device ID.  This can be any device ID which is unique to the INT Domain.  This source ID can be the 6 byte MAC address of the source device followed by 2 bytes of 0x0000.

### DS Flags

The Domain Speecific Flags are set as follows:

* bit 0 The source-only data was set by the source device
* bit 1 The source-only data was set by the gateway on the customer premises
* bit 2 The source-only data was set by a switch outside of the customer premises
* The reaminng bits are reserved

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
  <span style='mso-spacerun:yes'> </span></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Hop 1 Switch ID
  <span style='mso-spacerun:yes'> </span></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=32 height=21 class=xl67 style='height:16.0pt'>Originating Device
  MAC Most signifigant 4 octets<span style='mso-spacerun:yes'> </span></td>
 </tr>
 <tr height=21 style='height:16.0pt'>
  <td colspan=16 height=21 class=xl67 style='height:16.0pt'>Originating Device
  MAC least signifigant 2 octets</td>
  <td colspan=16 class=xl67>Reserved = <font color="red">0x0000</font></td>
 </tr>
</table>
