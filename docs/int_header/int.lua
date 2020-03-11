-- This reflects the INT header prior to the updated documentation

function octet_to_mac(buff)
    addr = ""
    for i = 0,5,1
    do
        octect = buff(i,1):uint()
        addr = addr  .. string.format("%02X", octect)
        if i < 5
        then
            addr = addr .. ":"
        end
    end
    return addr
end

-- INT protocol example
-- declare our protocol
tps_proto = Proto("TPS_INT","TPS INT Protocol")
-- create a function to dissect it

function tps_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "TPS INT"
    total_hops = 1

    -- UDP Encapsulation Header - 4 bytes
    local subtree = tree:add(tps_proto,buffer(0,20),"In-band Network Telemetry (INT)")

    udp_int_buf = buffer(0,4)
    udp_tree = subtree:add(udp_int_buf(),"UDP Encapsulation")
    udp_tree:add("sport: " .. udp_int_buf(0,1):uint())
    udp_tree:add("dport: " .. udp_int_buf(1,1):uint())
    udp_tree:add("len: " .. udp_int_buf(2,1):uint())
    udp_tree:add("cksum: " .. udp_int_buf(3,1):uint())

    -- INT Shim Header - 4 bytes
    shim_buf = buffer(4,8)
    shim_tree = subtree:add(buffer(4,8),"INT Shim Header")
    shim_tree:add("Type: " .. shim_buf(0,1):bitfield(0,4))
    shim_tree:add("NPT: " .. shim_buf(1,1):bitfield(4,2))
    shim_tree:add("res1: " .. shim_buf(2,1):bitfield(6,2))
    local length = shim_buf(3,1):uint()
    shim_tree:add("length: " .. length)
    shim_tree:add("res2: " .. shim_buf(4,1):uint())
    shim_tree:add("next_proto: " .. shim_buf(5,1):uint())

    -- INT Metadata Header - 12 bytes
    header_tree = subtree:add(buffer(12,12), "INT Metadata Header")
    tvbr = buffer(20,12)
    header_tree:add("Version: " .. tvbr:bitfield(0,4))
    header_tree:add("Res: " .. tvbr:bitfield(4,2))
    header_tree:add("d: " .. tvbr:bitfield(6,1))
    header_tree:add("e: " .. tvbr:bitfield(7,1))
    header_tree:add("m: " .. tvbr:bitfield(8,1))
    header_tree:add("Reserved: " .. tvbr:bitfield(9,10))
--    metalen = tvbr:bitfield(19,5)
    header_tree:add("Per-hop Metadata Length: " .. tvbr:bitfield(19,5))
    header_tree:add("Remaining Hop count: " .. buffer(5,1):uint())
    header_tree:add("Instruction Bitmap: " .. buffer(6,1):uint())
    header_tree:add("Domain ID: " .. buffer(7,1):uint())
    header_tree:add(buffer(8,2),"Domain-specific Instruction: " ..  buffer(8,2):uint())

    -- INT Metadata Stack - 4 bytes
    header_offset = 16
    total_hops = 1 + ((length - 3 - 4)/metalen)
    if total_hops > 1 then
        stack_length = 12 + (total_hops-1)*4*metalen
    else
        stack_length = total_hops*4*metalen
    end
    subtree = subtree:add(buffer(header_offset,stack_length),"Metadata Stack")
    while (total_hops >= 2)
    do
        metaTree = subtree:add(buffer(header_offset,(metalen)),"Hop " .. total_hops)
        switch_id = buffer(header_offset,4):uint()
        metaTree:add(buffer(header_offset,4),"Switch ID: " .. switch_id)
        total_hops = total_hops - 1
        header_offset = header_offset + (metalen*4)
    end
    metaTree = subtree:add(buffer(header_offset,(metalen)),"Hop " .. 1)
    switch_id = buffer(header_offset,4):uint()
    metaTree:add(buffer(header_offset,4),"Switch ID: " .. switch_id)
    device_mac = octet_to_mac(buffer(header_offset+4,6))
    metaTree:add(buffer(header_offset+4,6),"Originating Device MAC address: " .. device_mac)
    -- UDP
    header_offset = header_offset + 12
    if next_proto == 0x11 then
        Dissector.get("udp"):call(buffer:range(header_offset):tvb(), pinfo, tree)
    elseif next_proto == 0x06 then
        Dissector.get("tcp"):call(buffer:range(header_offset):tvb(), pinfo, tree)
    end
end
ip_table = DissectorTable.get("ip.proto")
ip_table:add(253,tps_proto)

--ipv6_table = DissectorTable.get("ip.nh")
--ipv6_table:add(253,tps_proto)
