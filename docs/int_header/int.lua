-- This reflects the INT header prior to the updated documentation

function octet_to_mac(buff)
    local addr = ""
    for i = 0,5,1
    do
        local octect = buff(i,1):uint()
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

    local buf_offset = 0

    -- UDP Encapsulation Header - 8 bytes
    local int_tree = tree:add(tps_proto,buffer(0,20),"In-band Network Telemetry (INT)")

    -- INT Shim Header - 4 bytes
    local shim_buf = buffer(buf_offset,4)
    buf_offset = buf_offset + 4

    local shim_tree = int_tree:add(shim_buf,"INT Shim Header")
    shim_tree:add("Type: " .. shim_buf:bitfield(0,4))
    shim_tree:add("NPT: " .. shim_buf:bitfield(4,2))
    shim_tree:add("res1: " .. shim_buf:bitfield(6,2))
    local length = shim_buf:bitfield(8,8)
    shim_tree:add("length: " .. length)
    shim_tree:add("res2: " .. shim_buf:bitfield(16,8))
    local next_proto = shim_buf:bitfield(24,8)
    shim_tree:add("next_proto: " .. next_proto)

    -- INT Metadata Header - 12 bytes
    local tvbr = buffer(buf_offset,12)
    buf_offset = buf_offset + 12

    local header_tree = int_tree:add(tvbr, "INT Metadata Header")
    header_tree:add("Version: " .. tvbr:bitfield(0,4))
    header_tree:add("Res: " .. tvbr:bitfield(4,2))
    header_tree:add("d: " .. tvbr:bitfield(6,1))
    header_tree:add("e: " .. tvbr:bitfield(7,1))
    header_tree:add("m: " .. tvbr:bitfield(8,1))
    header_tree:add("Reserved: " .. tvbr:bitfield(9,10))
    local metalen = tvbr:bitfield(19,5)
    header_tree:add("Per-hop Metadata Length: " .. metalen)
    header_tree:add("Remaining Hop count: " .. tvbr:bitfield(24,8))
    header_tree:add("Instruction Bitmap: " .. tvbr:bitfield(32,16))
    header_tree:add("Domain ID: " .. tvbr:bitfield(48,16))
    header_tree:add("Instructions: " .. tvbr:bitfield(64,16))
    header_tree:add("DS 1: " .. tvbr:bitfield(70,1))
    header_tree:add("DS 2: " .. tvbr:bitfield(71,1))
    header_tree:add("DS 3: " .. tvbr:bitfield(72,1))
    header_tree:add("DS balance: " .. tvbr:bitfield(73,13))

    -- INT Metadata Stack - 4 bytes
    local total_hops = length - 6
    local buf_bytes = total_hops * 4 + 6 + 2
    local int_md_buf = buffer(buf_offset,buf_bytes)
    buf_offset = buf_offset + buf_bytes

    local int_tree = int_tree:add(int_md_buf,"Metadata Stack")
    local int_md_buf_offset = 0
    local metaTree
    while (total_hops > 0)
    do
        local metaTree = int_tree:add(int_md_buf(0,1),"Hop " .. total_hops)
        local switch_id = int_md_buf(int_md_buf_offset,4):uint()
        metaTree:add("Switch ID: " .. switch_id)
        int_md_buf_offset = int_md_buf_offset + 4
        if total_hops == 1 then
            local device_mac = octet_to_mac(int_md_buf(int_md_buf_offset,6))
            metaTree:add(int_md_buf(int_md_buf_offset,6),"Originating Device MAC address: " .. device_mac)
            int_md_buf_offset = int_md_buf_offset + 6
            metaTree:add("Padding: " .. int_md_buf(int_md_buf_offset,2))
            int_md_buf_offset = int_md_buf_offset + 2
        end
        total_hops = total_hops - 1
    end

--    local device_mac = octet_to_mac(int_md_buf(int_md_buf_offset,6))
--    metaTree:add(int_md_buf(int_md_buf_offset,6),"Originating Device MAC address: " .. device_mac)

    if next_proto == 0x11 then
        -- UDP
        Dissector.get("udp"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
    elseif next_proto == 0x06 then
        -- TCP
        Dissector.get("tcp"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
    end
end

ip_table = DissectorTable.get("udp.port")
ip_table:add(555,tps_proto)
