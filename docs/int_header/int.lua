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

    -- INT Shim Header
    header_offset = 0
    total_hops = 1
    type = buffer(0,1):uint()
    reserved = buffer(1,1):uint()
    length = buffer(2,1):uint()
    next_proto = buffer(3,1):uint()
    local subtree = tree:add(tps_proto,buffer(header_offset,length),"In-band Network Telemetry (INT)")
    shim_tree = subtree:add(buffer(header_offset,4),"INT Shim Header")
    shim_tree:add(buffer(0,1),"Type: " .. type)
    shim_tree:add(buffer(1,1),"Reserved: " .. reserved)
    shim_tree:add(buffer(2,1),"Length: " .. length)
    shim_tree:add(buffer(3,1),"Next Protocol: " .. next_proto)

    -- INT Metadata Header
    header_tree = subtree:add(buffer(4,8), "INT Metadata Header")
    tvbr = buffer(4,1)
    version = tvbr:bitfield(0,4)
    header_tree:add("Version: " .. version)
    replication = tvbr:bitfield(4,2)
    header_tree:add("Replication: " .. replication)
    copy = tvbr:bitfield(6,1)
    header_tree:add("Copy: " .. copy)
    hop_exceeded = tvbr:bitfield(7,1)
    header_tree:add("Max Hop count exceeded: " .. hop_exceeded)
    tvbr = buffer(5,2)
    mtu = tvbr:bitfield(0,1)
    header_tree:add("MTU Exceeded: " .. mtu)
    reserved = tvbr:bitfield(1,10)
    header_tree:add("Reserved: " .. reserved)
    metalen = tvbr:bitfield(11,5)
    header_tree:add("Per-hop Metadata Length: " .. metalen)
    rem_hop_count = buffer(7,1):uint()
    header_tree:add(buffer(7,1),"Remaining Hop count: " .. rem_hop_count)
    inst_bitmap = buffer(8,2):uint()
    header_tree:add(buffer(8,2),"Instruction Bitmap: " .. inst_bitmap)
    reserved = buffer(10,2):uint()
    header_tree:add(buffer(10,2),"Reserved: " .. reserved)

    -- INT Metadata Stack
    total_hops = (length - 12)/metalen
    header_offset = 12
    subtree = subtree:add(buffer(header_offset,metalen*total_hops),"Metadata Stack")
    while (total_hops >= 1)
    do
        metaTree = subtree:add(buffer(header_offset,metalen),"Hop " .. total_hops)
        switch_id = buffer(header_offset,4):uint()
        metaTree:add(buffer(header_offset,4),"Switch ID: " .. switch_id)
        device_mac = octet_to_mac(buffer(header_offset+4,6))
        metaTree:add(buffer(header_offset+4,6),"Originating Device MAC address: " .. device_mac)
        total_hops = total_hops - 1
        header_offset = header_offset + metalen
    end

    -- UDP
    header_offset = header_offset + (metalen * total_hops)
    if next_proto == 0x11 then
        Dissector.get("udp"):call(buffer:range(header_offset):tvb(), pinfo, tree)
    end
end
ip_table = DissectorTable.get("ip.proto")
ip_table:add(253,tps_proto)