-- ################################################
-- #    Xbox One Smartglass protocol dissector    #
-- #            by tuxuser (2017)                 #
-- ################################################

-- declare protocol
smartglass_proto = Proto("XBSG", "Xbox One SmartGlass Protocol")

-- Convenience field adding code from: https://github.com/Lekensteyn/kdnet/blob/master/kdnet.lua
-- Thx Mr. Peter Wu (Lekensteyn)
local hf = {}
function add_field(proto_field_constructor, name, desc, ...)
    local field_name = "xbox_sg." .. name
    name = string.gsub(name, "%.", "_")
    -- If the description is omitted, use the name as label
    if type(desc) == "string" then
        hf[name] = proto_field_constructor(field_name, desc, ...)
    else
        hf[name] = proto_field_constructor(field_name, name, desc, ...)
    end
end
-- Convenience function to add many fields at once. The definition list contains
-- field types followed by (multiple) field names. An empty string can be used
-- for alignment.
-- Field types are integers, 64 is ULONG64, 16 is USHORT, etc.
function add_fields(defs)
    local typemap = {
        [64] = ProtoField.uint64,
        [32] = ProtoField.uint32,
        [16] = ProtoField.uint16,
        [8] = ProtoField.uint8,
    }
    local field_type
    local field_args = {}
    for _, def in ipairs(defs) do
        if type(def) == "number" then
            field_type = typemap[def] or ProtoField.bytes
        elseif type(def) == "table" then
            field_args = def
        elseif #def > 0 then
            add_field(field_type, def, table.unpack(field_args))
        end
    end
end
function add_fields_to_tree(defs, tvb, pinfo, tree, selection)
    local size
    if not selection then selection = {0, tvb:len()} end
    local offset, buffer_size = -selection[1], selection[2]
    for _, def in ipairs(defs) do
        if type(def) == "number" then
            size = def / 8
        elseif type(def) == "string" then
            if #def > 0 and offset >= 0 and offset + size <= buffer_size then
                assert(hf[def], "Unknown field " .. def)
                tree:add(hf[def], tvb(offset, size))
            end
            offset = offset + size
        end
    end
    return offset
end

function invert(tbl)
    local rv = {}
    for key,val in pairs( tbl ) do rv[ val ] = key end
    return rv
end

-- create a function to dissect it

smartglass_proto.prefs["aes_key"] =
    Pref.string("Expanded Secret", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "AES")

packet_types = {
    [0xDD00] = "DiscoveryRequest",
    [0xDD01] = "DiscoveryResponse",
    [0xDD02] = "PowerOnRequest",
    [0xCC00] = "ConnectRequest",
    [0xCC01] = "ConnectResponse",
    [0xD00D] = "Message"
}

add_field(ProtoField.uint16, "packet_type", "Packet Type", base.HEX_DEC, packet_types)

--[[
'unprotected_payload_length' / Default(Int16ub, 0),
'protected_payload_length' / If(
    FieldIn('pkt_type', [PacketType.ConnectRequest, PacketType.ConnectResponse]),
    Default(Int16ub, 0)
),
'version' / Default(Int16ub, 2)
-]]

message_types = {
    [0x1] = "Ack",
    [0x2] = "Group",
    [0x3] = "LocalJoin",
    [0x5] = "StopActivity",
    [0x19] = "AuxilaryStream",
    [0x1A] = "ActiveSurfaceChange",
    [0x1B] = "Navigate",
    [0x1C] = "Json",
    [0x1D] = "Tunnel",
    [0x1E] = "ConsoleStatus",
    [0x1F] = "TitleTextConfiguration",
    [0x20] = "TitleTextInput",
    [0x21] = "TitleTextSelection",
    [0x22] = "MirroringRequest",
    [0x23] = "TitleLaunch",
    [0x26] = "StartChannelRequest",
    [0x27] = "StartChannelResponse",
    [0x28] = "StopChannel",
    [0x29] = "System",
    [0x2A] = "Disconnect",
    [0x2E] = "TitleTouch",
    [0x2F] = "Accelerometer",
    [0x30] = "Gyrometer",
    [0x31] = "Inclinometer",
    [0x32] = "Compass",
    [0x33] = "Orientation",
    [0x36] = "PairedIdentityStateChanged",
    [0x37] = "Unsnap",
    [0x38] = "GameDvrRecord",
    [0x39] = "PowerOff",
    [0xF00] = "MediaControllerRemoved",
    [0xF01] = "MediaCommand",
    [0xF02] = "MediaCommandResult",
    [0xF03] = "MediaState",
    [0xF0A] = "Gamepad",
    [0xF2B] = "SystemTextConfiguration",
    [0xF2C] = "SystemTextInput",
    [0xF2E] = "SystemTouch",
    [0xF34] = "SystemTextAck",
    [0xF35] = "SystemTextDone"
}

--[[
    'protected_payload_length' / Default(Int16ub, 0),
    'sequence_number' / Int32ub,
    'target_participant_id' / Int32ub,
    'source_participant_id' / Int32ub,
    'flags' / BitStruct(
        'version' / Default(BitsInteger(2), 2),
        'need_ack' / Flag,
        'is_fragment' / Flag,
        'msg_type' / BitsInteger(12)
    ),
    'channel_id' / Int64ub
--]]

header_bitmask = {
    ["version"] = 0xC000,
    ["need_ack"] = 0x2000,
    ["is_fragment"] = 0x1000,
    ["msg_type"] = 0xFFF,
}

add_field(ProtoField.bytes, "message.header", "Message Header", base.SPACE)
add_field(ProtoField.uint16, "message.header.protected_payload_length", "Protected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint32, "message.header.sequence", "Sequence Number", base.DEC)
add_field(ProtoField.uint32, "message.header.target_id", "Target Participant Id", base.HEX_DEC)
add_field(ProtoField.uint32, "message.header.source_id", "Source Participant Id", base.HEX_DEC)
add_field(ProtoField.uint16, "message.header.flags", "Flags", base.HEX)
add_field(ProtoField.uint16, "message.header.flags.version", "Version", base.DEC, nil, header_bitmask.version) -- 2 bits
add_field(ProtoField.bool, "message.header.flags.need_ack", "Need Ack", 16, nil, header_bitmask.need_ack) -- 1 bit
add_field(ProtoField.bool, "message.header.flags.is_fragment", "Is Fragment", 16, nil, header_bitmask.is_fragment) -- 1 bit
add_field(ProtoField.uint16, "message.header.flags.msg_type", "Message Type", base.DEC, message_types, header_bitmask.msg_type) -- 12 bits
add_field(ProtoField.uint64, "message.header.channel_id", "Channel Id", base.HEX_DEC)

add_field(ProtoField.none, "message.protected_payload", "Protected Payload")
add_field(ProtoField.none, "message.hash", "Hash")


-- PowerOn request fields
add_field(ProtoField.uint16, "poweron_request.unprotected_payload_length", "Unprotected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint16, "poweron_request.version", "Version", base.HEX_DEC)
add_field(ProtoField.none, "poweron_request.unprotected_payload", "Unprotected Payload")
add_field(ProtoField.uint16, "poweron_request.liveid_length", "Live ID Length", base.HEX_DEC)
add_field(ProtoField.string, "poweron_request.liveid", "Live ID")

-- Discovery request fields
add_field(ProtoField.uint16, "discovery_request.unprotected_payload_length", "Unprotected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_request.version", "Version", base.HEX_DEC)
add_field(ProtoField.none, "discovery_request.unprotected_payload", "Unprotected Payload")
add_field(ProtoField.uint32, "discovery_request.flags", "Flags", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_request.client_type", "Client Type", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_request.minimum_version", "Minimum Version", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_request.maximum_version", "Maximum Version", base.HEX_DEC)

-- Discovery response fields
add_field(ProtoField.uint16, "discovery_response.unprotected_payload_length", "Unprotected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_response.version", "Version", base.HEX_DEC)
add_field(ProtoField.none, "discovery_response.unprotected_payload", "Unprotected Payload")
add_field(ProtoField.uint32, "discovery_response.flags", "Flags", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_response.device_type", "Device Type", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_response.name_length", "Name Length", base.HEX_DEC)
add_field(ProtoField.string, "discovery_response.name", "Name")
add_field(ProtoField.uint16, "discovery_response.uuid_length", "UUID Length", base.HEX_DEC)
add_field(ProtoField.string, "discovery_response.uuid", "UUID")
add_field(ProtoField.uint32, "discovery_response.last_error", "Last Error", base.HEX_DEC)
add_field(ProtoField.uint16, "discovery_response.certificate_length", "Certificate Length", base.HEX_DEC)
add_field(ProtoField.bytes, "discovery_response.certificate", "Certificate", base.SPACE)

publickey_types = {
    [0x00] = "EC_DH_P256",
    [0x01] = "EC_DH_P384",
    [0x02] = "EC_DH_P521",
    [0xFFFF] = "Default"
}

-- Connect request fields
add_field(ProtoField.uint16, "connect_request.unprotected_payload_length", "Unprotected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint16, "connect_request.protected_payload_length", "Protected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint16, "connect_request.version", "Version", base.HEX_DEC)
add_field(ProtoField.none, "connect_request.unprotected_payload", "Unprotected Payload")
add_field(ProtoField.bytes, "connect_request.uuid", "UUID", base.SPACE)
add_field(ProtoField.uint16, "connect_request.public_key_type", "PublicKey Type", base.HEX_DEC, publickey_types)
add_field(ProtoField.bytes, "connect_request.public_key", "PublicKey", base.SPACE)
add_field(ProtoField.bytes, "connect_request.iv", "IV", base.SPACE)
add_field(ProtoField.none, "connect_request.protected_payload", "Protected Payload")
add_field(ProtoField.none, "connect_request.hash", "Hash")

-- Connect response fields
add_field(ProtoField.uint16, "connect_response.unprotected_payload_length", "Unprotected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint16, "connect_response.protected_payload_length", "Protected Payload Length", base.HEX_DEC)
add_field(ProtoField.uint16, "connect_response.version", "Version", base.HEX_DEC)
add_field(ProtoField.none, "connect_response.unprotected_payload", "Unprotected Payload")
add_field(ProtoField.bytes, "connect_response.iv", "IV", base.SPACE)
add_field(ProtoField.none, "connect_response.protected_payload", "Protected Payload")
add_field(ProtoField.none, "connect_response.hash", "Hash")

-- IMPORTANT: Add the fields to the proto
smartglass_proto.fields = hf

--- Messages
function parse_message(tvbuf, tree)
    local flags_range = tvbuf(14, 2)
    tree:add(hf.message_header, tvbuf(0, 24))
    tree:add(hf.message_header_protected_payload_length, tvbuf(0, 2))
    tree:add(hf.message_header_sequence, tvbuf(2, 4))
    tree:add(hf.message_header_target_id, tvbuf(6, 4))
    tree:add(hf.message_header_source_id, tvbuf(10, 4))
    tree:add(hf.message_header_flags, flags_range)
    tree:add(hf.message_header_flags_version, flags_range)
    tree:add(hf.message_header_flags_need_ack, flags_range)
    tree:add(hf.message_header_flags_is_fragment, flags_range)
    tree:add(hf.message_header_flags_msg_type, flags_range)
    tree:add(hf.message_header_channel_id, tvbuf(16, 8))
    -- Manually parsing message message type
    local msg_type = bit.band(flags_range:uint(), header_bitmask.msg_type)
    -- Forward to payload
    tvbuf = tvbuf(24)
    protected_payload = tvbuf(0, tvbuf:len() - 32)
    hash = tvbuf(tvbuf:len() - 32)
    tree:add(hf.message_protected_payload, protected_payload)
    tree:add(hf.message_hash, hash)
    return msg_type
end

--- Simple messages
function parse_connect_response(tvbuf, tree)
    local unprotected_payload_length = tvbuf(0, 2):uint()
    tree:add(hf.connect_response_unprotected_payload_length, tvbuf(0, 2))
    tree:add(hf.connect_response_protected_payload_length, tvbuf(2, 2))
    tree:add(hf.connect_response_version, tvbuf(4, 2))
    -- Forward to unprotected payload
    tvbuf = tvbuf(6)
    tree:add(hf.connect_response_unprotected_payload, tvbuf(0, unprotected_payload_length))
    tree:add(hf.connect_response_iv, tvbuf(0, 16))
    -- Forward to protected payload
    tvbuf = tvbuf(16)
    protected_payload = tvbuf(0, tvbuf:len() - 32)
    hash = tvbuf(tvbuf:len() - 32)
    tree:add(hf.connect_response_protected_payload, protected_payload)
    tree:add(hf.connect_response_hash, hash)
end

function parse_connect_request(tvbuf, tree)
    local unprotected_payload_length = tvbuf(0, 2):uint()
	tree:add(hf.connect_request_unprotected_payload_length, tvbuf(0, 2))
	tree:add(hf.connect_request_protected_payload_length, tvbuf(2, 2))
	tree:add(hf.connect_request_version, tvbuf(4, 2))
	-- Forward to unprotected payload
	tvbuf = tvbuf(6)
	tree:add(hf.connect_request_unprotected_payload, tvbuf(0, unprotected_payload_length))
	tree:add(hf.connect_request_uuid, tvbuf(0, 16))
    tree:add(hf.connect_request_public_key_type, tvbuf(16, 2))
    local keysize = 0
    local keytype = tvbuf(16, 2):uint()
    if keytype == 0x00 then
        -- EC_DH_P256
        keysize = 0x40
    elseif keytype == 0x01 then
        -- EC_DH_P384
        keysize = 0x60
    elseif keytype == 0x02 then
        -- EC_DH_P521
        keysize = 0x84
    end
	tree:add(hf.connect_request_public_key, tvbuf(18, keysize))
	tree:add(hf.connect_request_iv, tvbuf(18 + keysize, 16))
	-- Forward to protected payload
	tvbuf = tvbuf(98)
    protected_payload = tvbuf(0, tvbuf:len() - 32)
    hash = tvbuf(tvbuf:len() - 32)
	tree:add(hf.connect_request_protected_payload, protected_payload)
    tree:add(hf.connect_request_hash, hash)
end

function parse_poweron_request(tvbuf, tree)
    local unprotected_payload_length = tvbuf(0, 2):uint()
    tree:add(hf.poweron_request_unprotected_payload_length, tvbuf(0, 2))
    tree:add(hf.poweron_request_version, tvbuf(2, 2))
    -- Forward to unprotected payload
    tvbuf = tvbuf(4)
    -- Null terminator included (+1)
    local liveid_length = tvbuf(0, 2):uint() + 1
    tree:add(hf.poweron_request_unprotected_payload, tvbuf(0, unprotected_payload_length))
    tree:add(hf.poweron_request_liveid_length, tvbuf(0, 2))
    tree:add(hf.poweron_request_liveid, tvbuf(2, liveid_length))
end

function parse_discovery_response(tvbuf, tree)
    local unprotected_payload_length = tvbuf(0, 2):uint()
    tree:add(hf.discovery_response_unprotected_payload_length, tvbuf(0, 2))
    tree:add(hf.discovery_response_version, tvbuf(2, 2))
    -- Forward to unprotected payload
    tvbuf = tvbuf(4)
    -- Null terminator included (+1)
    local name_length = tvbuf(6, 2):uint() + 1
    local uuid_length = tvbuf(8 + name_length, 2):uint() + 1
    tree:add(hf.discovery_response_unprotected_payload, tvbuf(0, unprotected_payload_length))
    tree:add(hf.discovery_response_flags, tvbuf(0, 4))
    tree:add(hf.discovery_response_device_type, tvbuf(4, 2))
    tree:add(hf.discovery_response_name_length, tvbuf(6, 2))
    tree:add(hf.discovery_response_name, tvbuf(8, name_length))
    tree:add(hf.discovery_response_uuid_length, tvbuf(8 + name_length, 2))
    tree:add(hf.discovery_response_uuid, tvbuf(10 + name_length, uuid_length))
    -- Forward to certificate length + certificate
    tvbuf = tvbuf(10 + name_length + uuid_length)
    -- For whatever reason, size of cert is off by 1 byte
    local certificate_length = tvbuf(0, 2):uint() - 1
    tree:add(hf.discovery_response_last_error, tvbuf(0, 4))
    tree:add(hf.discovery_response_certificate_length, tvbuf(4, 2))
    tree:add(hf.discovery_response_certificate, tvbuf(6, certificate_length))
end

function parse_discovery_request(tvbuf, tree)
    local unprotected_payload_length = tvbuf(0, 2):uint()
    tree:add(hf.discovery_request_unprotected_payload_length, tvbuf(0, 2))
    tree:add(hf.discovery_request_version, tvbuf(2, 2))
    -- Forward to unprotected payload
    tvbuf = tvbuf(4)
    tree:add(hf.discovery_request_unprotected_payload, tvbuf(0, unprotected_payload_length))
    tree:add(hf.discovery_request_flags, tvbuf(0, 4))
    tree:add(hf.discovery_request_client_type, tvbuf(4, 2))
    tree:add(hf.discovery_request_minimum_version, tvbuf(6, 2))
    tree:add(hf.discovery_request_maximum_version, tvbuf(8, 2))
end

function smartglass_proto.dissector(tvbuf, pinfo, tree)
    pinfo.cols.protocol = smartglass_proto.name
    local subtree = tree:add(tvbuf(), smartglass_proto.name)
    local packet_type_str = packet_types[tvbuf(0, 2):uint()]
    subtree:add(hf.packet_type, tvbuf(0, 2))

    local data = tvbuf(2)
    if "DiscoveryRequest" == packet_type_str then
        parse_discovery_request(data, subtree)
    elseif "DiscoveryResponse" == packet_type_str then
        parse_discovery_response(data, subtree)
    elseif "PowerOnRequest" == packet_type_str then
        parse_poweron_request(data, subtree)
    elseif "ConnectRequest" == packet_type_str then
        parse_connect_request(data, subtree)
    elseif "ConnectResponse" == packet_type_str then
        parse_connect_response(data, subtree)
    elseif "Message" == packet_type_str then
        local msg_type = parse_message(data, subtree)
        packet_type_str = string.format("%s [%s]", packet_type_str, message_types[msg_type])
    end
    pinfo.cols.info = packet_type_str
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 5050
udp_table:add(5050,smartglass_proto)
