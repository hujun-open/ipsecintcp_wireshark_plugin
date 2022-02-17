ipsectcp_proto = Proto("ipsecintcp",  "IPsec encaped in TCP RFC8229")
message_length = ProtoField.uint16("ipsecintcp.message_length", "Length", base.DEC)
non_esp_marker = ProtoField.none("ipsecintcp.nonespmarker","Non-ESP Marker")
ipsectcp_proto.fields = {message_length,non_esp_marker}

function ipsectcp_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end
    pinfo.cols.protocol = ipsectcp_proto.name
    local subtree = tree:add(ipsectcp_proto, buffer(), "IPsec in TCP RFC8229")
    if buffer:range():string() == "IKETCP" then
        pinfo.cols.info = "IPsecinTCP Stream Prefix"
        return
    end
    subtree:add(message_length, buffer(0,2))
    if length>6 then
        if buffer:bytes(2,4):tohex() == "00000000" then
          subtree:add(non_esp_marker, buffer(2,4))
          Dissector.get("isakmp"):call(buffer(6):tvb(), pinfo, tree)
        else
          Dissector.get("esp"):call(buffer(2):tvb(), pinfo, tree)
        end
    end
end

  local tcp_port = DissectorTable.get("tcp.port")
-- decode all TCP pkt with port 4500 as above
  tcp_port:add(4500, ipsectcp_proto)