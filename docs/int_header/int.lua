-- Copyright (c) 2019 Cable Television Laboratories, Inc.
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--    http://www.apache.org/licenses/LICENSE-2.0
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-- This Wireshark plugin outputs the TPS Telemetry Report & INT packets

-- Declare our protocols
tps_udp_proto = Proto("TPS_INT", "TPS UDP INT Protocol")
tps_trpt_proto = Proto("TRPT_INT", "Transparency Report UDP INT Protocol")


function octet_to_mac(buff)
    local addr = ""
    for i = 0,5,1
    do
        local octect = buff(i, 1):uint()
        --noinspection StringConcatenationInLoops
        addr = addr  .. string.format("%02X", octect)
        if i < 5
        then
            --noinspection StringConcatenationInLoops
            addr = addr .. ":"
        end
    end
    return addr
end

function tps_int_shim(int_tree, shim_buf)
    -- UDP INT Shim Header - 4 bytes
    local shim_tree = int_tree:add(shim_buf, "UDP INT Shim Header")
    shim_tree:add("Type: " .. shim_buf:bitfield(0, 4))
    shim_tree:add("NPT: " .. shim_buf:bitfield(4, 2))
    assert(shim_buf:bitfield(6, 2)) -- reserved
    local length = shim_buf:bitfield(8, 8)
    shim_tree:add(shim_buf(1, 1), "length: " .. length)
    assert(shim_buf:bitfield(16, 8)) -- reserved
    local next_proto = shim_buf:bitfield(24, 8)
    shim_tree:add(shim_buf(3, 1), "next_proto: " .. next_proto)
    return length, next_proto
end


function bit_tree_8(tree, buf, buf_index, index, tree_label, item_label)
    local bit_tree = tree:add(buf(buf_index, 1), tree_label)
    bit_tree:add(item_label .. " 0: " .. buf:bitfield(index, 1))
    bit_tree:add(item_label .. " 1: " .. buf:bitfield(index + 1, 1))
    bit_tree:add(item_label .. " 2: " .. buf:bitfield(index + 2, 1))
    bit_tree:add(item_label .. " 3: " .. buf:bitfield(index + 3, 1))
    bit_tree:add(item_label .. " 4: " .. buf:bitfield(index + 4, 1))
    bit_tree:add(item_label .. " 5: " .. buf:bitfield(index + 5, 1))
    bit_tree:add(item_label .. " 6: " .. buf:bitfield(index + 6, 1))
    bit_tree:add(item_label .. " 7: " .. buf:bitfield(index + 7, 1))
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
    header_tree:add("Version: " .. tvbr:bitfield(0, 4))
    header_tree:add("d: " .. tvbr:bitfield(6, 1))
    header_tree:add("e: " .. tvbr:bitfield(7, 1))
    header_tree:add("m: " .. tvbr:bitfield(8, 1))
    header_tree:add("Per-hop Metadata Length: " .. tvbr:bitfield(19, 5))
    header_tree:add(tvbr(3, 1), "Remaining Hop count: " .. tvbr:bitfield(24, 8))
    bit_tree_16(header_tree, tvbr, 4, 32, "Instructions", "bit")
    header_tree:add(tvbr(6, 2), "Domain ID: " .. tvbr:bitfield(48, 16))
    bit_tree_16(header_tree, tvbr, 8, 64, "DS Instructions", "bit")
    bit_tree_16(header_tree, tvbr, 10, 80, "DS Flags", "bit")
end


function tps_int_md(int_tree, int_md_buf, total_hops)
    -- INT Metadata Stack - 4 bytes
    local int_tree = int_tree:add(int_md_buf, "Metadata Stack")
    local int_md_buf_offset = 0
    while (total_hops > 0)
    do
        local tree_bytes = 4
        if total_hops == 1 then
            tree_bytes = 12
        end

        local metaTree = int_tree:add(int_md_buf(int_md_buf_offset, tree_bytes), "Hop " .. total_hops)
        local switch_id = int_md_buf(int_md_buf_offset, 4):uint()
        metaTree:add(int_md_buf(int_md_buf_offset, 4), "Switch ID: " .. switch_id)
        int_md_buf_offset = int_md_buf_offset + 4
        if total_hops == 1 then
            local device_mac = octet_to_mac(int_md_buf(int_md_buf_offset, 6))
            metaTree:add(int_md_buf(int_md_buf_offset, 6), "Originating Device MAC address: " .. device_mac)
            int_md_buf_offset = int_md_buf_offset + 6
            local pad = int_md_buf(int_md_buf_offset, 2)
            assert(pad)
            int_md_buf_offset = int_md_buf_offset + 2
        end
        total_hops = total_hops - 1
    end
end


function tps_trpt_hdr(header_tree, tvbr)
    header_tree:add("Version: " .. tvbr:bitfield(0, 4))
    header_tree:add("Hardware ID: " .. tvbr:bitfield(4, 6))
    header_tree:add("Sequence No: " .. tvbr:bitfield(10, 22))
    header_tree:add(tvbr(4, 4), "Node ID: " .. tvbr:bitfield(32, 32))
    header_tree:add("Type 1: " .. tvbr:bitfield(64, 4))
    header_tree:add("In Proto: " .. tvbr:bitfield(68, 4))
    header_tree:add(tvbr(9, 1), "Length: " .. tvbr:bitfield(72, 8))
    header_tree:add(tvbr(10, 2), "Domain ID: " .. tvbr:bitfield(80, 16))
    header_tree:add(tvbr(12, 1), "d: " .. tvbr:bitfield(96, 1))
    header_tree:add(tvbr(12, 1), "q: " .. tvbr:bitfield(97, 1))
    header_tree:add(tvbr(12, 1), "f: " .. tvbr:bitfield(98, 1))
    header_tree:add(tvbr(12, 1), "i: " .. tvbr:bitfield(99, 1))
    assert(tvbr:bitfield(100, 4)) -- reserved
    bit_tree_16(header_tree, tvbr, 13, 16, "Rep MD", "bit")
    bit_tree_8(header_tree, tvbr, 15, 8, "DS MD", "bit")
    header_tree:add(tvbr(16, 4), "Var Opt MD: " .. tvbr:bitfield(124, 32))
end


function trpt_eth_hdr(trpt_tree, tvbr)
    local eth_tree = trpt_tree:add(tvbr, "Telemetry Report Ethernet Header")
    eth_tree:add(tvbr(0,6), "Dest MAC: " .. octet_to_mac(tvbr(0, 6)))
    eth_tree:add(tvbr(6,6), "Source MAC: " .. octet_to_mac(tvbr(6, 6)))
    local ether_type = tvbr:bitfield(96, 16)
    eth_tree:add(tvbr(12,2), "Ether Type: " .. ether_type)
    return ether_type
end


function tps_udp_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TPS INT"
    local shim_buf = buffer(0, 4)
    local buf_offset = 4
    local tvbr = buffer(buf_offset, 12)
    buf_offset = buf_offset + 12
    local length = shim_buf:bitfield(8, 8)
    local total_hops = length - 6
    local buf_bytes = total_hops * 4 + 6 + 2

    -- INT Shim Header - 8 bytes
    local int_tree = tree:add(tps_udp_proto, buffer(0, 16+buf_bytes), "In-band Network Telemetry (INT)")
    local length, next_proto = tps_int_shim(int_tree, shim_buf)

    -- INT Metadata Header - 12 bytes
    tps_int_hdr(int_tree, tvbr)

    -- INT Metadata Stack - 4 bytes
    local total_hops = length - 6
    local buf_bytes = total_hops * 4 + 6 + 2
    local int_md_buf = buffer(buf_offset, buf_bytes)
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


function tps_trpt_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TRPT/INT"

    -- TRPT Header - 20 bytes
    local trpt_buf = buffer(buf_offset, 20)
    local buf_offset = 20
    local trpt_tree = tree:add(tps_trpt_proto, trpt_buf, "Telemetry Report")
    tps_trpt_hdr(trpt_tree, trpt_buf)

    -- INT Ethernet
    Dissector.get("ethertype"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
    local trpt_eth_buf = buffer(buf_offset, 14)
    buf_offset = buf_offset + 14
    local ether_type = trpt_eth_hdr(tree, trpt_eth_buf)
    local ip_buf = buffer(buf_offset, 20)
    if ether_type == 0x0800 then
        Dissector.get("ip"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
        buf_offset = buf_offset + 24
    elseif ether_type == 0x86dd then
        Dissector.get("ipv6"):call(buffer:range(buf_offset):tvb(), pinfo, tree)
        buf_offset = buf_offset + 20
    end
end


-- INT protocol example
ip_table = DissectorTable.get("udp.port")
ip_table:add(555, tps_udp_proto)
ip_table:add(556, tps_trpt_proto)
