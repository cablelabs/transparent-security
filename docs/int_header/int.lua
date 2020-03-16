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
tps_udp_proto = Proto("TPS_INT","TPS UDP INT Protocol")
-- create a function to dissect it

function tps_int_shim(int_tree, shim_buf)
    -- UDP INT Shim Header - 4 bytes
    local shim_tree = int_tree:add(shim_buf,"UDP INT Shim Header")
    shim_tree:add("Type: " .. shim_buf:bitfield(0,4))
    shim_tree:add("NPT: " .. shim_buf:bitfield(4,2))
    local length = shim_buf:bitfield(8,8)
    shim_tree:add("length: " .. length)
    local next_proto = shim_buf:bitfield(24,8)
    shim_tree:add("next_proto: " .. next_proto)
    return length, next_proto
end

function bit_tree_16(tree, buf, buf_index, index, tree_label, item_label)
    local bit_tree = tree:add(buf(buf_index, 2), tree_label)
    bit_tree:add(item_label .. " 0: " .. buf:bitfield(index, 1))
    bit_tree:add(item_label .. " 1: " .. buf:bitfield(index + 1, 1))
    bit_tree:add(item_label .. " 2: " .. buf:bitfield(index + 2, 1))
    bit_tree:add(item_label .. " 3: " .. buf:bitfield(index + 3, 1))
    bit_tree:add(item_label .. " 4: " .. buf:bitfield(index + 4, 1))
    bit_tree:add(item_label .. " 5: " .. buf:bitfield(index + 5, 1))
    bit_tree:add(item_label .. " 6: " .. buf:bitfield(index + 6, 1))
    bit_tree:add(item_label .. " 7: " .. buf:bitfield(index + 7, 1))
    bit_tree:add(item_label .. " 8: " .. buf:bitfield(index + 8, 1))
    bit_tree:add(item_label .. " 9: " .. buf:bitfield(index + 9, 1))
    bit_tree:add(item_label .. " 10: " .. buf:bitfield(index + 10, 1))
    bit_tree:add(item_label .. " 11: " .. buf:bitfield(index + 11, 1))
    bit_tree:add(item_label .. " 12: " .. buf:bitfield(index + 12, 1))
    bit_tree:add(item_label .. " 13: " .. buf:bitfield(index + 13, 1))
    bit_tree:add(item_label .. " 14: " .. buf:bitfield(index + 14, 1))
    bit_tree:add(item_label .. " 15: " .. buf:bitfield(index + 15, 1))
end

function tps_int_hdr(int_tree, tvbr)
    local header_tree = int_tree:add(tvbr, "INT Metadata Header")
    header_tree:add("Version: " .. tvbr:bitfield(0,4))
    header_tree:add("d: " .. tvbr:bitfield(6,1))
    header_tree:add("e: " .. tvbr:bitfield(7,1))
    header_tree:add("m: " .. tvbr:bitfield(8,1))
    header_tree:add("Per-hop Metadata Length: " .. tvbr:bitfield(19,5))
    header_tree:add("Remaining Hop count: " .. tvbr:bitfield(24,8))
    bit_tree_16(header_tree, tvbr, 4, 32, "Instructions", "bit")
    header_tree:add("Domain ID: " .. tvbr:bitfield(48,16))
    bit_tree_16(header_tree, tvbr, 8, 64, "DS Instructions", "bit")
    bit_tree_16(header_tree, tvbr, 10, 80, "DS Flags", "bit")
end


function tps_int_md(int_tree, int_md_buf, total_hops)
    -- INT Metadata Stack - 4 bytes
    local int_tree = int_tree:add(int_md_buf,"Metadata Stack")
    local int_md_buf_offset = 0
    while (total_hops > 0)
    do
        local tree_bytes = 4
        if total_hops == 1 then
            tree_bytes = 10
        end
        local metaTree = int_tree:add(int_md_buf(int_md_buf_offset, tree_bytes),"Hop " .. total_hops)

        local switch_id = int_md_buf(int_md_buf_offset,4):uint()
        metaTree:add("Switch ID: " .. switch_id)
        int_md_buf_offset = int_md_buf_offset + 4
        if total_hops == 1 then
            local device_mac = octet_to_mac(int_md_buf(int_md_buf_offset,6))
            metaTree:add(int_md_buf(int_md_buf_offset,6),"Originating Device MAC address: " .. device_mac)
            int_md_buf_offset = int_md_buf_offset + 6
            int_md_buf(int_md_buf_offset,2) -- get padding but don't display
            int_md_buf_offset = int_md_buf_offset + 2
        end
        total_hops = total_hops - 1
    end

    if next_proto == 0x11 then
        -- UDP
        Dissector.get("udp"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
    elseif next_proto == 0x06 then
        -- TCP
        Dissector.get("tcp"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
    end
end


function tps_udp_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "TPS INT"

    local buf_offset = 0

    -- UDP Encapsulation Header - 8 bytes
    local int_tree = tree:add(tps_udp_proto,buffer(0,20),"In-band Network Telemetry (INT)")

    local shim_buf = buffer(buf_offset,4)
    buf_offset = buf_offset + 4
    local length, next_proto = tps_int_shim(int_tree, shim_buf)

    -- INT Metadata Header - 12 bytes
    local tvbr = buffer(buf_offset,12)
    buf_offset = buf_offset + 12
    tps_int_hdr(int_tree, tvbr)


    -- INT Metadata Stack - 4 bytes
    local total_hops = length - 6
    local buf_bytes = total_hops * 4 + 6 + 2
    local int_md_buf = buffer(buf_offset,buf_bytes)
    buf_offset = buf_offset + buf_bytes
    tps_int_md(int_tree, int_md_buf, total_hops)

    if next_proto == 0x11 then
        -- UDP
        Dissector.get("udp"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
    elseif next_proto == 0x06 then
        -- TCP
        Dissector.get("tcp"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
    end
end

ip_table = DissectorTable.get("udp.port")
ip_table:add(555,tps_udp_proto)
