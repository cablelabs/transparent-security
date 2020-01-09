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

function ip_to_string(buff)
    addr = ""
    for i = 0,3,1
    do
      octect = buff(i,1):uint()
      addr = addr  .. string.format("%d", octect)
      if i < 3
      then
         addr = addr .. "."
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
    local subtree = tree:add(tps_proto,buffer(),"TPS INT Protocol Data")
    orig_addr = "Origional Source " .. octet_to_mac(buffer(0,6))
    subtree:add(buffer(0,6),orig_addr)
    source_ip = "Source IP " .. ip_to_string(buffer(6,4))
    subtree:add(buffer(6,4),source_ip)
    dst_ip = "Destination IP " .. ip_to_string(buffer(10,4))
    subtree:add(buffer(10,4),dst_ip)
    dst_port = "Destination Port " .. string.format("%d", buffer(14,2):uint())
    subtree:add(buffer(14,2),dst_port)
    if buffer(16,2):uint() == 0x0800
    then
        Dissector.get("ip"):call(buffer:range(18):tvb(), pinfo, tree)
    end
end
eth_table = DissectorTable.get("ethertype")
eth_table:add(0x1212,tps_proto)