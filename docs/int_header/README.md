# In-band Network Telemetry Header

## Header definition

The header is defined in [INT Header defintion](INT_header.md)

## Wireshark plug-in

Note: This version of the plug-in matches what is currently implemented in
the miniment simulator implementation and may be behind the current documentation
header definition.

[plugin](int.lua)

Usage:

```bash
wireshark -X lua_script:./int.lua
```
