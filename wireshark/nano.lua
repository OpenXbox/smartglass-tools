-- ################################################
-- # Xbox Nano (Gamestreaming) protocol dissector #
-- #            by tuxuser (2017)                 #
-- ################################################

-- declare protocol
nano_proto = Proto("NANO-RTP", "Xbox Nano Protocol")

-- Convenience field adding code from: https://github.com/Lekensteyn/kdnet/blob/master/kdnet.lua
-- Thx Mr. Paul Wu (Lekensteyn)
local hf = {}
function add_field(proto_field_constructor, name, desc, ...)
    local field_name = "nano." .. name
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

local assigned_channels = {
}

local channel_class = {
    Video = "Microsoft::Rdp::Dct::Channel::Class::Video",
    Audio = "Microsoft::Rdp::Dct::Channel::Class::Audio",
    ChatAudio = "Microsoft::Rdp::Dct::Channel::Class::ChatAudio",
    Control = "Microsoft::Rdp::Dct::Channel::Class::Control",
    Input = "Microsoft::Rdp::Dct::Channel::Class::Input",
    InputFeedback = "Microsoft::Rdp::Dct::Channel::Class::Input Feedback"

}

local channel_string = {
    [channel_class.Video] = "VIDEO",
    [channel_class.Audio] = "AUDIO",
    [channel_class.ChatAudio] = "CHATAUDIO",
    [channel_class.Control] = "CONTROL",
    [channel_class.Input] = "INPUT",
    [channel_class.InputFeedback] = "INPUTFEEDBACK"
}

-- HEADER
local payload_type = {
    StreamerMessage = 0x23,
    ControlHandshake = 0x60,
    ChannelControl = 0x61,
    FEC = 0x62,
    UDPHandshake = 0x64
}
local payload_type_string = invert(payload_type)

local header_bitmask = {
    version = 0xC000,
    padding = 0x2000,
    extension = 0x1000,
    csrc_count = 0xF00,
    marker = 0x80,
    payload_type = 0x7F
}

local fields = nano_proto.fields
add_field(ProtoField.none, "header", "# RTP Header #")
add_field(ProtoField.uint16, "header_flags", "Flags", base.HEX)
add_field(ProtoField.uint16, "header_flags_version", "Version", base.DEC, nil, header_bitmask.version) -- 2 bits
add_field(ProtoField.bool, "header_flags_padding", "Padding", 16, nil, header_bitmask.padding) -- 1 bit
add_field(ProtoField.bool, "header_flags_extension", "Extension", 16, nil, header_bitmask.extension) -- 1 bit
add_field(ProtoField.uint16, "header_flags_csrc_count", "CSRC Count", base.DEC, nil, header_bitmask.csrc_count) -- 4 bits
add_field(ProtoField.bool, "header_flags_marker", "Marker", 16, nil, header_bitmask.marker) -- 1 bit
add_field(ProtoField.uint16, "header_flags_payload_type", "Payload Type", base.HEX_DEC, payload_type_string, header_bitmask.payload_type) -- 7 bits

add_field(ProtoField.uint16, "header_sequence_num", "Sequence Num", base.DEC)
add_field(ProtoField.uint32, "header_timestamp", "Timestamp", base.HEX_DEC)

add_field(ProtoField.uint32, "header_ssrc", "SSRC", base.HEX)
add_field(ProtoField.uint16, "header_ssrc_connection_id", "Connection Id", base.HEX_DEC)
add_field(ProtoField.uint16, "header_ssrc_channel_id", "Channel Id", base.HEX_DEC) 

-- Control Handshake
add_field(ProtoField.bytes, "control_handshake", "ControlProtocol Handshake", base.SPACE)
add_field(ProtoField.uint8, "control_handshake_type", "Type", base.HEX_DEC)
add_field(ProtoField.uint16, "control_handshake_connection_id", "Connection Id", base.HEX_DEC)

-- Channel Control
local channel_control_type = {
    ChannelCreate = 0x2,
    ChannelOpen = 0x3,
    ChannelClose = 0x4
}
local channel_control_type_string = invert(channel_control_type)


add_field(ProtoField.none, "channel_control", "# Channel Control #")
add_field(ProtoField.uint32, "channel_control_type", "Type", base.HEX_DEC, channel_control_type_string)

add_field(ProtoField.bytes, "channel_control_create", "Channel Create", base.SPACE)
add_field(ProtoField.uint16, "channel_control_create_name_len", "Name Length", base.HEX_DEC)
add_field(ProtoField.string, "channel_control_create_name", "Name", base.ASCII)
add_field(ProtoField.uint32, "channel_control_create_flags", "Flags", base.HEX)

add_field(ProtoField.bytes, "channel_control_open", "Channel Open", base.SPACE)
add_field(ProtoField.uint32, "channel_control_open_flags_sz", "Flags Size", base.DEC)
add_field(ProtoField.bytes, "channel_control_open_flags", "Flags", base.SPACE)

add_field(ProtoField.bytes, "channel_control_close", "Channel Close", base.SPACE)
add_field(ProtoField.uint32, "channel_control_close_reason", "Reason", base.HEX_DEC)

-- UDPHandshake
add_field(ProtoField.none, "udp_handshake", "# UDP Handshake #")
add_field(ProtoField.uint8, "udp_handshake_unknown", "Unknown", base.HEX_DEC)

-- FEC Data
add_field(ProtoField.none, "fec_data", "# FEC DATA #")
add_field(ProtoField.uint8, "fec_data_type", "Type", base.HEX_DEC)
add_field(ProtoField.uint32, "fec_data_unk2", "Unknown 2", base.HEX_DEC)
add_field(ProtoField.uint16, "fec_data_unk3", "Unknown 3", base.HEX_DEC)
add_field(ProtoField.uint8, "fec_data_unk4", "Unknown 4", base.HEX_DEC)
add_field(ProtoField.uint16, "fec_data_payload_size", "Payload Size", base.HEX_DEC)
add_field(ProtoField.bytes, "fec_data_payload", "Payload", base.SPACE)

-- StreamerMessage
local streamer_type_audio_video = {
    ServerHandshake = 0x1,
    ClientHandshake = 0x2,
    Control = 0x3,
    Data = 0x4
}
local streamer_type_audio_video_string = invert(streamer_type_audio_video)

local streamer_type_input = {
    ServerHandshake = 0x1,
    ClientHandshake = 0x2,
    FrameAck = 0x3,
    Frame = 0x4
}
local streamer_type_input_string = invert(streamer_type_input)

local streamer_type_control = {
    StreamerMessageWithHeader = 0x00
}
local streamer_type_control_string = invert(streamer_type_control)


local streamer_message_string = {
    [channel_class.Video] = streamer_type_audio_video_string,
    [channel_class.Audio] = streamer_type_audio_video_string,
    [channel_class.ChatAudio] = streamer_type_audio_video_string,
    [channel_class.Control] = streamer_type_control_string,
    [channel_class.Input] = streamer_type_input_string,
    [channel_class.InputFeedback] = streamer_type_input_string
}

add_field(ProtoField.none, "streamer_msg", "# StreamerMessage #")
add_field(ProtoField.uint32, "streamer_msg_flags", "Flags", base.HEX)
add_field(ProtoField.uint32, "streamer_msg_sequence_num", "Sequence Num", base.DEC)
add_field(ProtoField.uint32, "streamer_msg_prev_sequence_num", "Prev Sequence Num", base.DEC)
add_field(ProtoField.uint32, "streamer_msg_packet_type", "Packet Type", base.HEX_DEC)
add_field(ProtoField.uint32, "streamer_msg_payload_size", "Payload Size", base.HEX_DEC)

-- VIDEO messages
local video_codec = {
    H264 = 0x0,
    YUV = 0x1,
    RGB = 0x2
}
local video_codec_string = invert(video_codec)

local video_control_bitmask = {
    LastDisplayedFrame = 0x1,
    LostFrames = 0x2,
    QueueDepth = 0x4,
    StopStream = 0x8,
    StartStream = 0x10,
    RequestKeyframe = 0x20
}

add_field(ProtoField.none, "video_format", "# Video Format #")
add_field(ProtoField.uint32, "video_format_fps", "FPS", base.DEC)
add_field(ProtoField.uint32, "video_format_width", "Width", base.DEC)
add_field(ProtoField.uint32, "video_format_height", "Height", base.DEC)
add_field(ProtoField.uint32, "video_format_codec", "Codec", base.DEC, video_codec_string)
add_field(ProtoField.uint32, "video_format_bpp", "Bpp", base.DEC)
add_field(ProtoField.uint32, "video_format_bytes", "Bytes", base.HEX_DEC)
add_field(ProtoField.uint64, "video_format_redmask", "Red Mask", base.HEX)
add_field(ProtoField.uint64, "video_format_greenmask", "Green Mask", base.HEX)
add_field(ProtoField.uint64, "video_format_bluemask", "Blue Mask", base.HEX)

add_field(ProtoField.none, "video_server_handshake", "# Video - Server Handshake #")
add_field(ProtoField.uint32, "video_server_handshake_protocol_version", "Protocol Version", base.DEC)
add_field(ProtoField.uint32, "video_server_handshake_width", "Width", base.DEC)
add_field(ProtoField.uint32, "video_server_handshake_height", "Height", base.DEC)
add_field(ProtoField.uint32, "video_server_handshake_fps", "FPS", base.DEC)
add_field(ProtoField.uint64, "video_server_handshake_reference_timestamp", "Reference Timestamp", base.HEX_DEC)
add_field(ProtoField.uint32, "video_server_handshake_format_count", "Format Count", base.DEC)
add_field(ProtoField.none, "video_server_handshake_formats", "Formats")

add_field(ProtoField.none, "video_client_handshake", "# Video - Client Handshake #")
add_field(ProtoField.uint32, "video_client_handshake_initial_frameid", "Initial Frame Id", base.HEX_DEC)
add_field(ProtoField.none, "video_client_handshake_requested_format", "Requested Format")

add_field(ProtoField.none, "video_control", "# Video - Control #")
add_field(ProtoField.uint32, "video_control_flags", "Flags", base.HEX)
add_field(ProtoField.bool, "video_control_flags_request_keyframe", "Request Keyframe", 32, nil, video_control_bitmask.RequestKeyframe)
add_field(ProtoField.bool, "video_control_flags_start_stream", "Start Stream", 32, nil, video_control_bitmask.StartStream)
add_field(ProtoField.bool, "video_control_flags_stop_stream", "Stop Stream", 32, nil, video_control_bitmask.StopStream)
add_field(ProtoField.bool, "video_control_flags_queue_depth", "Queue Depth", 32, nil, video_control_bitmask.QueueDepth)
add_field(ProtoField.bool, "video_control_flags_lost_frames", "Lost Frames", 32, nil, video_control_bitmask.LostFrames)
add_field(ProtoField.bool, "video_control_flags_last_displayed_frame", "Last Displayed Frame", 32, nil, video_control_bitmask.LastDisplayedFrame)
add_field(ProtoField.uint32, "video_control_last_displayed_frame", "Last Displayed Frame", base.HEX_DEC)
add_field(ProtoField.uint64, "video_control_timestamp", "Timestamp", base.HEX_DEC)
add_field(ProtoField.uint32, "video_control_queue_depth", "Queue Depth", base.HEX_DEC)
add_field(ProtoField.uint32, "video_control_first_lost_frame", "First Lost Frame", base.HEX_DEC)
add_field(ProtoField.uint32, "video_control_last_lost_frame", "Last Lost Frame", base.HEX_DEC)

add_field(ProtoField.none, "video_data", "# Video - Data #")
add_field(ProtoField.uint32, "video_data_flags", "Flags", base.HEX)
add_field(ProtoField.uint32, "video_data_frameid", "Frame Id", base.HEX_DEC)
add_field(ProtoField.uint64, "video_data_timestamp", "Timestamp", base.HEX_DEC)
add_field(ProtoField.uint32, "video_data_total_size", "Total Size", base.HEX_DEC)
add_field(ProtoField.uint32, "video_data_packet_count", "Packet Count", base.DEC)
add_field(ProtoField.uint32, "video_data_offset", "Offset", base.HEX_DEC)
add_field(ProtoField.uint32, "video_data_data_length", "Data Length", base.HEX_DEC)
add_field(ProtoField.none, "video_data_data", "Data", base.HEX_DEC)

-- CHAT/AUDIO messages
local audio_codec = {
    Opus = 0x0,
    AAC = 0x1,
    PCM = 0x2
}
local audio_codec_string = invert(audio_codec)

local audio_bitdepth = {
    Integer = 0x0,
    Float = 0x1
}
local audio_bitdepth_string = invert(audio_bitdepth)

local audio_control_bitmask = {
    StopStream = 0x8,
    StartStream = 0x10,
    Reinitialize = 0x40
}

add_field(ProtoField.none, "audio_format", "# Audio Format #")
add_field(ProtoField.uint32, "audio_format_channels", "Channels", base.DEC)
add_field(ProtoField.uint32, "audio_format_samplerate", "Samplerate", base.DEC)
add_field(ProtoField.uint32, "audio_format_codec", "Codec", base.DEC, audio_codec_string)
add_field(ProtoField.uint32, "audio_format_bitdepth", "Bit Depth", base.DEC)
add_field(ProtoField.uint32, "audio_format_type", "Type", base.DEC, audio_bitdepth_string)

add_field(ProtoField.none, "audio_server_handshake", "# Audio - Server Handshake #")
add_field(ProtoField.uint32, "audio_server_handshake_protocol_version", "Protocol Version", base.DEC)
add_field(ProtoField.uint64, "audio_server_handshake_reference_timestamp", "Reference Timestamp", base.HEX_DEC)
add_field(ProtoField.uint32, "audio_server_handshake_format_count", "Format Count", base.DEC)
add_field(ProtoField.none, "audio_server_handshake_formats", "Formats")

add_field(ProtoField.none, "audio_client_handshake", "# Audio - Client Handshake #")
add_field(ProtoField.uint32, "audio_client_handshake_initial_frameid", "Initial Frame Id", base.HEX_DEC)
add_field(ProtoField.none, "audio_client_handshake_requested_format", "Requested Format")

add_field(ProtoField.none, "audio_control", "# Audio - Control #")
add_field(ProtoField.uint32, "audio_control_flags", "Flags", base.HEX)
add_field(ProtoField.bool, "audio_control_flags_reinitialize", "Reinitialize", 32, nil, audio_control_bitmask.Reinitialize)
add_field(ProtoField.bool, "audio_control_flags_start_stream", "Start Stream", 32, nil, audio_control_bitmask.StartStream)
add_field(ProtoField.bool, "audio_control_flags_stop_stream", "Stop Stream", 32, nil, audio_control_bitmask.StopStream)

add_field(ProtoField.none, "audio_data", "# Audio - Data #")
add_field(ProtoField.uint32, "audio_data_flags", "Flags", base.HEX)
add_field(ProtoField.uint32, "audio_data_frameid", "Frame Id", base.HEX_DEC)
add_field(ProtoField.uint64, "audio_data_timestamp", "Timestamp", base.HEX_DEC)
add_field(ProtoField.uint32, "audio_data_data_length", "Data Length", base.HEX_DEC)
add_field(ProtoField.none, "audio_data_data", "Data")

-- CONTROL messages
local streamer_msg_opcode = {
    Unknown = 0x0,
    SessionInit = 0x1,
    SessionCreate = 0x2,
    SessionCreateResponse = 0x3,
    SessionDestroy = 0x4,
    VideoStatistics = 0x5,
    RealtimeTelemetry = 0x6,
    ChangeVideoQuality = 0x7,
    InitiateNetworkTest = 0x8,
    NetworkInformation = 0x9,
    NetworkTestResponse = 0xA,
    ControllerEvent = 0xB
}
local streamer_msg_opcode_string = invert(streamer_msg_opcode) 

add_field(ProtoField.none, "control", "# Control Protocol #")
add_field(ProtoField.uint32, "control_prev_sequence", "Previous Sequence (DUP)", base.DEC)
add_field(ProtoField.uint16, "control_unknown1", "Unknown1", base.HEX_DEC)
add_field(ProtoField.uint16, "control_unknown2", "Unknown2", base.HEX_DEC)
add_field(ProtoField.uint16, "control_opcode", "Message OpCode", base.HEX_DEC, streamer_msg_opcode_string)

-- INPUT messages
add_field(ProtoField.none, "input_server_handshake", "# Input - Server Handshake #")
add_field(ProtoField.uint32, "input_server_handshake_protocol_version", "Protocol Version", base.DEC)
add_field(ProtoField.uint32, "input_server_handshake_desktop_width", "Desktop Width", base.DEC)
add_field(ProtoField.uint32, "input_server_handshake_desktop_height", "Desktop Height", base.DEC)
add_field(ProtoField.uint32, "input_server_handshake_max_touches", "Max Touches", base.DEC)
add_field(ProtoField.uint32, "input_server_handshake_initial_frameid", "Initial Frame Id", base.DEC)

add_field(ProtoField.none, "input_client_handshake", "# Input - Client Handshake #")
add_field(ProtoField.uint32, "input_client_handshake_max_touches", "Max Touches", base.DEC)
add_field(ProtoField.uint64, "input_client_handshake_reference_timestamp", "Reference Timestamp", base.HEX_DEC)

add_field(ProtoField.none, "input_frameack", "# Input - Frame Ack #")
add_field(ProtoField.uint32, "input_frameack_frameack", "Frame Ack", base.HEX_DEC)

add_field(ProtoField.none, "input_frame", "# Input - Frame #")
add_field(ProtoField.uint32, "input_frame_frameid", "Frame", base.HEX_DEC)
add_field(ProtoField.uint64, "input_frame_timestamp", "Timestamp (sent)", base.HEX_DEC)
add_field(ProtoField.uint64, "input_frame_created_ts", "Timestamp (created)", base.HEX_DEC)
add_field(ProtoField.bytes, "input_frame_buttons", "Buttons", base.SPACE)
add_field(ProtoField.uint8, "input_frame_left_trigger", "Left Trigger", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_right_trigger", "Right Trigger", base.HEX_DEC)
add_field(ProtoField.uint16, "input_frame_left_thumb_x", "Left Thumb X-Axis", base.HEX_DEC)
add_field(ProtoField.uint16, "input_frame_left_thumb_y", "Left Thumb Y-Axis", base.HEX_DEC)
add_field(ProtoField.uint16, "input_frame_right_thumb_x", "Right Thumb X-Axis", base.HEX_DEC)
add_field(ProtoField.uint16, "input_frame_right_thumb_y", "Right Thumb Y-Axis", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_trigger_l", "Rumble Trigger (L)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_trigger_r", "Rumble Trigger (R)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_handle_l", "Rumble Handle (L)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_handle_r", "Rumble Handle (R)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_byte6", "Byte 6", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_byte7", "Byte 7", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_trigger_l2", "Rumble Trigger (L/Dup)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_trigger_r2", "Rumble Trigger (R/Dup)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_handle_l2", "Rumble Handle (L/Dup)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_rumble_handle_r2", "Rumble Handle (R/Dup)", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_byte12", "Byte 12", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_byte13", "Byte 13", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_byte14", "Byte 14", base.HEX_DEC)

add_field(ProtoField.uint8, "input_frame_keyboardstate", "KeyboardState", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_mousestate", "MouseState", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_touchstate", "TouchState", base.HEX_DEC)
add_field(ProtoField.uint8, "input_frame_gamepadstate", "GamepadState", base.HEX_DEC)

-- STREAMER WITH HEADER messages
add_field(ProtoField.none, "change_video_quality", "# Change Video Quality #")
add_field(ProtoField.uint32, "change_video_quality_unk1", "Unknown1", base.HEX_DEC)
add_field(ProtoField.uint32, "change_video_quality_unk2", "Unknown2", base.HEX_DEC)
add_field(ProtoField.uint32, "change_video_quality_unk3", "Unknown3", base.HEX_DEC)
add_field(ProtoField.uint32, "change_video_quality_unk4", "Unknown4", base.HEX_DEC)
add_field(ProtoField.uint32, "change_video_quality_unk5", "Unknown5", base.HEX_DEC)
add_field(ProtoField.uint32, "change_video_quality_unk6", "Unknown6", base.HEX_DEC)

-- IMPORTANT: Add the fields to the proto
nano_proto.fields = hf

-- Want to retrieve the following fields later on
-- Read protocol from here, to distinguish TCP from UDP
ip_proto_f = Field.new("ip.proto")

-- Video Channel parsing
function parse_video_format(tvbuf, pinfo, tree)
    local video_format_length = 0
    local codec = tvbuf(12, 4):le_uint()
    if video_codec.RGB == codec then video_format_length = 48 else video_format_length = 16 end
    tree:add_le(hf.video_format, tvbuf(0, video_format_length))
    tree:add_le(hf.video_format_fps, tvbuf(0, 4))
    tree:add_le(hf.video_format_width, tvbuf(4, 4))
    tree:add_le(hf.video_format_height, tvbuf(8, 4))
    tree:add_le(hf.video_format_codec, tvbuf(12, 4))
    if video_codec.RGB == codec then
        tree:add_le(hf.video_format_bpp, tvbuf(16, 4))
        tree:add_le(hf.video_format_bytes, tvbuf(20, 4))
        tree:add_le(hf.video_format_red_mask, tvbuf(24, 8))
        tree:add_le(hf.video_format_green_mask, tvbuf(32, 8))
        tree:add_le(hf.video_format_blue_mask, tvbuf(40, 8))
    end
    return video_format_length
end

function parse_streamer_video_message(tvbuf, pinfo, tree, type)
    if streamer_type_audio_video.ClientHandshake == type then
        tree:add_le(hf.video_client_handshake, tvbuf)
        tree:add_le(hf.video_client_handshake_initial_frameid, tvbuf(0, 4))
        tree:add_le(hf.video_client_handshake_requested_format, tvbuf(4))
        parse_video_format(tvbuf(4), pinfo, tree)
    elseif streamer_type_audio_video.ServerHandshake == type then
        local format_count = tvbuf(24, 4):le_uint()
        local formats = tvbuf(28)
        local pos = 0
        tree:add_le(hf.video_server_handshake, tvbuf)
        tree:add_le(hf.video_server_handshake_protocol_version, tvbuf(0, 4))
        tree:add_le(hf.video_server_handshake_width, tvbuf(4, 4))
        tree:add_le(hf.video_server_handshake_height, tvbuf(8, 4))
        tree:add_le(hf.video_server_handshake_fps, tvbuf(12, 4))
        tree:add_le(hf.video_server_handshake_reference_timestamp, tvbuf(16, 8))
        tree:add_le(hf.video_server_handshake_format_count, tvbuf(24, 4))
        tree:add_le(hf.video_server_handshake_formats, tvbuf(28))
        for i=1, format_count do
            pos = pos + parse_video_format(formats(pos), pinfo, tree)
        end
    elseif streamer_type_audio_video.Control == type then
        local flags_range = tvbuf(0, 4)
        tree:add_le(hf.video_control, tvbuf)
        tree:add_le(hf.video_control_flags, flags_range)
        tree:add_le(hf.video_control_flags_request_keyframe, flags_range)
        tree:add_le(hf.video_control_flags_start_stream, flags_range)
        tree:add_le(hf.video_control_flags_stop_stream, flags_range)
        tree:add_le(hf.video_control_flags_queue_depth, flags_range)
        tree:add_le(hf.video_control_flags_lost_frames, flags_range)
        tree:add_le(hf.video_control_flags_last_displayed_frame, flags_range)
        local pos = 4
        if (bit.band(flags_range:uint(), video_control_bitmask.LastDisplayedFrame) ~= 0) then
            tree:add_le(hf.video_control_last_displayed_frame, data(pos, 4))
            tree:add_le(hf.video_control_timestamp, data(pos + 4, 8))
            pos = pos + 12
        end
        if (bit.band(flags_range:uint(), video_control_bitmask.QueueDepth) ~= 0) then
            tree:add_le(hf.video_control_queue_depth, data(pos, 4))
            pos = pos + 4
        end
        if (bit.band(flags_range:uint(), video_control_bitmask.LostFrames) ~= 0) then
            tree:add_le(hf.video_control_first_lost_frame, data(pos, 4))
            tree:add_le(hf.video_control_last_lost_frame, data(pos + 4, 4))
        end
    elseif streamer_type_audio_video.Data == type then
        tree:add_le(hf.video_data, tvbuf)
        tree:add_le(hf.video_data_flags, tvbuf(0, 4))
        tree:add_le(hf.video_data_frameid, tvbuf(4, 4))
        tree:add_le(hf.video_data_timestamp, tvbuf(8, 8))
        tree:add_le(hf.video_data_total_size, tvbuf(16, 4))
        tree:add_le(hf.video_data_packet_count, tvbuf(20, 4))
        tree:add_le(hf.video_data_offset, tvbuf(24, 4))
        tree:add_le(hf.video_data_data_length, tvbuf(28, 4))
        tree:add_le(hf.video_data_data, tvbuf(32))
    else
        tree:add(tvbuf, "Unknown Message Type!")
    end
end

-- Chat/Audio Channel parsing
function parse_audio_format(tvbuf, pinfo, tree)
    local audio_format_length = 0
    local codec = tvbuf(8, 4):le_uint()
    if audio_codec.PCM == codec then audio_format_length = 20 else audio_format_length = 12 end
    tree:add_le(hf.audio_format, tvbuf(0, audio_format_length))
    tree:add_le(hf.audio_format_channels, tvbuf(0, 4))
    tree:add_le(hf.audio_format_samplerate, tvbuf(4, 4))
    tree:add_le(hf.audio_format_codec, tvbuf(8, 4))
    if audio_codec.PCM == codec then
        tree:add_le(hf.audio_format_bitdepth, tvbuf(12, 4))
        tree:add_le(hf.audio_format_type, tvbuf(16, 4))
    end
    return audio_format_length
end

function parse_streamer_audio_message(tvbuf, pinfo, tree, type)
    if streamer_type_audio_video.ClientHandshake == type then
        tree:add_le(hf.audio_client_handshake, tvbuf)
        tree:add_le(hf.audio_client_handshake_initial_frameid, tvbuf(0, 4))
        tree:add_le(hf.audio_client_handshake_requested_format, tvbuf(4))
        parse_audio_format(tvbuf(4), pinfo, tree)
    elseif streamer_type_audio_video.ServerHandshake == type then
        local format_count = tvbuf(12, 4):le_uint()
        local formats = tvbuf(16)
        local pos = 0
        tree:add_le(hf.audio_server_handshake, tvbuf)
        tree:add_le(hf.audio_server_handshake_protocol_version, tvbuf(0, 4))
        tree:add_le(hf.audio_server_handshake_reference_timestamp, tvbuf(4, 8))
        tree:add_le(hf.audio_server_handshake_format_count, tvbuf(12, 4))
        tree:add_le(hf.audio_server_handshake_formats, tvbuf(16))
        for i=1, format_count do
            pos = pos + parse_audio_format(formats(pos), pinfo, tree)
        end
    elseif streamer_type_audio_video.Control == type then
        local flag_range = tvbuf(0, 4)
        tree:add_le(hf.audio_control, tvbuf)
        tree:add_le(hf.audio_control_flags, flag_range)
        tree:add_le(hf.audio_control_flags_reinitialize, flag_range)
        tree:add_le(hf.audio_control_flags_start_stream, flag_range)
        tree:add_le(hf.audio_control_flags_stop_stream, flag_range)
    elseif streamer_type_audio_video.Data == type then
        tree:add_le(hf.audio_data, tvbuf)
        tree:add_le(hf.audio_data_flags, tvbuf(0, 4))
        tree:add_le(hf.audio_data_frameid, tvbuf(4 ,4))
        tree:add_le(hf.audio_data_timestamp, tvbuf(8, 8))
        tree:add_le(hf.audio_data_data_length, tvbuf(16, 4))
        tree:add_le(hf.audio_data_data, tvbuf(20))
    else
        tree:add(tvbuf, "Unknown Message Type!")
    end
end

-- Control Channel parsing
function parse_streamer_message_with_header(tvbuf, pinfo, tree, type)
    local opcode = tvbuf(8, 2):le_uint()
    tree:add_le(hf.control, tvbuf)
    tree:add_le(hf.control_prev_sequence, tvbuf(0, 4))
    tree:add_le(hf.control_unknown1, tvbuf(4, 2))
    tree:add_le(hf.control_unknown2, tvbuf(6, 2))
    tree:add_le(hf.control_opcode, tvbuf(8, 2))
    tvbuf = tvbuf(10)
    if streamer_msg_opcode.ChangeVideoQuality == opcode then
        tree:add_le(hf.change_video_quality, tvbuf)
        tree:add_le(hf.change_video_quality_unk1, tvbuf(0, 4))
        tree:add_le(hf.change_video_quality_unk2, tvbuf(4, 4))
        tree:add_le(hf.change_video_quality_unk3, tvbuf(8, 4))
        tree:add_le(hf.change_video_quality_unk4, tvbuf(12, 4))
        tree:add_le(hf.change_video_quality_unk5, tvbuf(16, 4))
        tree:add_le(hf.change_video_quality_unk6, tvbuf(20, 4))
    elseif streamer_msg_opcode.RealtimeTelemetry == opcode then
        local entries = tvbuf(0, 2):le_uint()
        local length = tvbuf:len() - 2
        local pos = 2
        while pos < length do
            local key = tvbuf(pos, 2):le_uint()
            tree:add(tvbuf(pos, 2), "Key: "..tostring(key))
            pos = pos + 2
            local value = tvbuf(pos, 8):le_uint64()
            tree:add(tvbuf(pos, 8), "Value: "..tostring(value))
            pos = pos + 8
        end
    end
    pinfo.cols.info:append(" [CTRL: "..streamer_msg_opcode_string[opcode].."]")
    return opcode
end

-- Input Channel parsing
function parse_streamer_input_message(tvbuf, pinfo, tree, type)
    if streamer_type_input.ClientHandshake == type then
        tree:add_le(hf.input_client_handshake, tvbuf)
        tree:add_le(hf.input_client_handshake_max_touches, tvbuf(0, 4))
        tree:add_le(hf.input_client_handshake_reference_timestamp, tvbuf(4, 8))
    elseif streamer_type_input.ServerHandshake == type then
        tree:add_le(hf.input_server_handshake, tvbuf)
        tree:add_le(hf.input_server_handshake_protocol_version, tvbuf(0, 4))
        tree:add_le(hf.input_server_handshake_desktop_width, tvbuf(4, 4))
        tree:add_le(hf.input_server_handshake_desktop_height, tvbuf(8, 4))
        tree:add_le(hf.input_server_handshake_max_touches, tvbuf(12, 4))
        tree:add_le(hf.input_server_handshake_initial_frameid, tvbuf(16, 4))
    elseif streamer_type_input.FrameAck == type then
        tree:add_le(hf.input_frameack, tvbuf)
        tree:add_le(hf.input_frameack_frameack, tvbuf(0, 4))
    elseif streamer_type_input.Frame == type then
        tree:add_le(hf.input_frame, tvbuf)
        tree:add_le(hf.input_frame_frameid, tvbuf(0, 4))
        tree:add_le(hf.input_frame_timestamp, tvbuf(4, 8))
        tree:add_le(hf.input_frame_created_ts, tvbuf(12, 8))
        tree:add_le(hf.input_frame_buttons , tvbuf(20, 16))
        tree:add_le(hf.input_frame_left_trigger, tvbuf(36, 1))
        tree:add_le(hf.input_frame_right_trigger, tvbuf(37, 1))
        tree:add_le(hf.input_frame_left_thumb_x, tvbuf(38, 2))
        tree:add_le(hf.input_frame_left_thumb_y, tvbuf(40, 2))
        tree:add_le(hf.input_frame_right_thumb_x, tvbuf(42, 2))
        tree:add_le(hf.input_frame_right_thumb_y, tvbuf(44, 2))
        tree:add_le(hf.input_frame_rumble_trigger_l, tvbuf(46, 1))
        tree:add_le(hf.input_frame_rumble_trigger_r, tvbuf(47, 1))
        tree:add_le(hf.input_frame_rumble_handle_l, tvbuf(48, 1))
        tree:add_le(hf.input_frame_rumble_handle_r, tvbuf(49, 1))
        tree:add_le(hf.input_frame_byte6, tvbuf(50, 1))
        tree:add_le(hf.input_frame_byte7, tvbuf(51, 1))
        tree:add_le(hf.input_frame_rumble_trigger_l2, tvbuf(52, 1))
        tree:add_le(hf.input_frame_rumble_trigger_r2, tvbuf(53, 1))
        tree:add_le(hf.input_frame_rumble_handle_l2, tvbuf(54, 1))
        tree:add_le(hf.input_frame_rumble_handle_r2, tvbuf(55, 1))
        tree:add_le(hf.input_frame_byte12, tvbuf(56, 1))
        tree:add_le(hf.input_frame_byte13, tvbuf(57, 1))
        tree:add_le(hf.input_frame_byte14, tvbuf(58, 1))
    else
        tree:add(tvbuf, "Unknown Message Type!")
    end
end

function parse_streamer_message(tvbuf, pinfo, tree, channel_id)
    local data = nil
    local packet_type = 0
    local chan_class = assigned_channels[channel_id]

    if ip_proto_f().value == 6 then
        -- TCP
        tree:add_le(hf.streamer_msg, tvbuf(0, 20))
        tree:add_le(hf.streamer_msg_flags, tvbuf(0, 4))
        tree:add_le(hf.streamer_msg_sequence_num, tvbuf(4, 4))
        tree:add_le(hf.streamer_msg_prev_sequence_num, tvbuf(8, 4))
        tree:add_le(hf.streamer_msg_packet_type, tvbuf(12, 4))
        if chan_class ~= channel_class.Control then
            tree:add_le(hf.streamer_msg_payload_size, tvbuf(16, 4))
            local payload_size = tvbuf(16, 4):le_uint()
            packet_type = tvbuf(12 ,4):le_uint()
            data = tvbuf(20, payload_size)
        else
            data = tvbuf(16)
        end

    else
        tree:add_le(hf.streamer_msg, tvbuf(0, 12))
        tree:add_le(hf.streamer_msg_flags, tvbuf(0, 4))
        tree:add_le(hf.streamer_msg_packet_type, tvbuf(4, 4))
        tree:add_le(hf.streamer_msg_payload_size, tvbuf(8, 4))
        local payload_size = tvbuf(8, 4):le_uint()
        packet_type = tvbuf(4, 4):le_uint()
        data = tvbuf(12, payload_size)
    end

    if channel_class.Video == chan_class then
        parse_streamer_video_message(data, pinfo, tree, packet_type)
    elseif (channel_class.Audio == chan_class) or 
           (channel_class.ChatAudio == chan_class) then
        parse_streamer_audio_message(data, pinfo, tree, packet_type)
    elseif (channel_class.Input == chan_class) or
            (channel_class.InputFeedback == chan_class) then
        parse_streamer_input_message(data, pinfo, tree, packet_type)
    elseif channel_class.Control == chan_class then
        parse_streamer_message_with_header(data, pinfo, tree, packet_type)
    end

    -- Control channel pinfo is set inside parse_streamer_message_with_header
    if chan_class ~= channel_class.Control then
        pinfo.cols.info:append(" ["..streamer_message_string[chan_class][packet_type].."]")
    end
    return packet_type
end

function parse_channel_control(tvbuf, pinfo, tree, channel_id)
    tree:add_le(hf.channel_control, tvbuf)
    tree:add_le(hf.channel_control_type, tvbuf(0, 4))
    -- Parsing type manually
    local type = tvbuf(0,4):le_uint()

    -- Assign new buffer, skipping leading type
    local data = tvbuf(4)
    if channel_control_type.ChannelCreate == type then
        local name_len = data(0,2):le_uint()
        local name = data(2, name_len):string()
        tree:add_le(hf.channel_control_create_name_len, data(0, 2))
        tree:add_le(hf.channel_control_create_name, data(2, name_len))
        tree:add_le(hf.channel_control_create_flags, data(name_len + 2, 4))
        -- Assign negotiated channel-class to channel-id
        assigned_channels[channel_id] = name

    elseif channel_control_type.ChannelOpen == type then
        local flags_len = data(0, 4):le_uint()
        tree:add_le(hf.channel_control_open_flags_sz, data(0, 4))
        if flags_len > 0 then
            tree:add_le(hf.channel_control_open_flags, data(4, flags_len))
        end

    elseif channel_control_type.ChannelClose == type then
        tree:add_le(hf.channel_control_close_reason, data(0, 4))
    end

    local chan_class = assigned_channels[channel_id]
    pinfo.cols.info:append(" ["..channel_control_type_string[type].."]")
    return type
end

function parse_fec_data(tvbuf, pinfo, tree)
    tree:add_le(hf.fec_data, tvbuf)
    
    tree:add_le(hf.fec_data_type, tvbuf(0, 1))
    tree:add_le(hf.fec_data_unk2, tvbuf(1, 4))
    tree:add_le(hf.fec_data_unk3, tvbuf(5, 2))
    tree:add_le(hf.fec_data_unk4, tvbuf(7, 1))
    tree:add_le(hf.fec_data_payload_size, tvbuf(8, 2))
    tree:add(hf.fec_data_payload, tvbuf(10))
end

function parse_udp_handshake(tvbuf, pinfo, tree)
    tree:add_le(hf.udp_handshake, tvbuf)
    tree:add_le(hf.udp_handshake_unknown, tvbuf(0, 1))
end

function parse_control_handshake(tvbuf, pinfo, tree)
    tree:add_le(hf.control_handshake, tvbuf)
    tree:add_le(hf.control_handshake_type, tvbuf(0, 1))
    tree:add_le(hf.control_handshake_connection_id, tvbuf(1, 2))
end

-- Returns (payload type, channel id, padding)
function parse_rtp_header(tvbuf, pinfo, tree)
    tree:add(hf.header, tvbuf)
    local flag_range = tvbuf(0, 2)
    tree:add(hf.header_flags, flag_range)
    tree:add(hf.header_flags_version, flag_range)
    tree:add(hf.header_flags_padding, flag_range)
    tree:add(hf.header_flags_extension, flag_range)
    tree:add(hf.header_flags_csrc_count, flag_range)
    tree:add(hf.header_flags_marker, flag_range)
    tree:add(hf.header_flags_payload_type, flag_range)
    tree:add(hf.header_sequence_num, tvbuf(2, 2))
    tree:add(hf.header_timestamp, tvbuf(4, 4))
    tree:add(hf.header_ssrc, tvbuf(8, 4))
    tree:add(hf.header_ssrc_connection_id, tvbuf(8, 2))
    tree:add(hf.header_ssrc_channel_id, tvbuf(10, 2))
    -- Root
    -- if csrc_count > 0 then
        -- Add csrc_count * uint32
    -- end
    -- Doing parsing manually...
    local version = bit32.rshift(bit.band(flag_range:uint(), header_bitmask.version), 14)
    local padding = (bit.band(flag_range:uint(), header_bitmask.padding) ~= 0)
    local extension = (bit.band(flag_range:uint(), header_bitmask.extension) ~= 0)
    local csrc_count = bit32.rshift(bit.band(flag_range:uint(), header_bitmask.csrc_count), 8)
    local marker = bit32.rshift(bit.band(flag_range:uint(), header_bitmask.marker), 7)
    local ptype = bit.band(flag_range:uint(), header_bitmask.payload_type)
    local sequence_num = tvbuf(2, 2):uint()
    local timestamp = tvbuf(4, 4):uint()
    local conn_id = tvbuf(8, 2):uint()
    local chan_id = tvbuf(10, 2):uint()

    -- Assign short name for column info
    local channel = ""
    -- Get stored channel-class for given channel id
    local channel_name = assigned_channels[chan_id]
    if channel_name ~= nil then
        channel = channel_string[channel_name]
    else
        channel = string.format("%i", chan_id)
    end

    pinfo.cols.info = ""
    if marker == 1 then
        pinfo.cols.info:append("[M] ")
    end
    pinfo.cols.info:append(string.format("CH=%s, SEQ=%u, TS=%u, PT=%s(0x%x)",
                            channel, sequence_num, timestamp, payload_type_string[ptype], ptype
    ))
    return ptype, chan_id, padding, marker
end

HEADER_SIZE = 12

-- Returns (payload type, channel id)
function parse_nano_packet(tvbuf, pinfo, tree)
    -- Parse header
    local header = tvbuf(0, HEADER_SIZE)
    local ptype, chan_id, padding_flag, marker_flag = parse_rtp_header(header, pinfo, tree)
    -- Parse body
    local padding_len = 0
    if padding_flag then
        padding_len = tvbuf(tvbuf:len() - 1, 1):uint()
    end
    local payload = tvbuf(HEADER_SIZE, tvbuf:len() - HEADER_SIZE - padding_len)
    if payload_type.ControlHandshake == ptype then
        parse_control_handshake(payload, pinfo, tree)
    elseif payload_type.ChannelControl == ptype then
        local type = parse_channel_control(payload, pinfo, tree, chan_id)
    elseif payload_type.StreamerMessage == ptype then
        parse_streamer_message(payload, pinfo, tree, chan_id)
    elseif payload_type.FEC == ptype then
        parse_fec_data(payload, pinfo, tree)
    elseif payload_type.UDPHandshake == ptype then
        parse_udp_handshake(payload, pinfo, tree)
    end
    -- Add Padding to the end of payload, if set
    if padding_flag then
        tree:add(tvbuf(tvbuf:len() - padding_len, padding_len), "Padding")
    end

    return ptype, chan_id
end

-- TCP packets need to be pre-processed
function process_nano_tcp(tvbuf, pinfo, tree)
    -- TCP packets can contain several chunks
    local chunks_in_packet = 0
    -- Keep track of current position in tvbuf
    local position = 0
    local total_length = tvbuf:len()

    -- Iterate through the packet
    while (position < total_length) do
        -- Read packet size
        local packet_size = tvbuf(position, 4):le_uint()
        position = position + 4
        -- Read actual packet into new buffer
        local data = tvbuf(position, packet_size)

        -- Check if we need to put info into subtree (just when having multiple payloads)
        if (position + packet_size) == tvbuf:len() and chunks_in_packet == 0 then
            -- Just one payload
            local ptype, chan_id = parse_nano_packet(data, pinfo, tree)
        else
            -- Multiple Payloads
            local subtree = tree:add(data, "-_-")
            local ptype, chan_id = parse_nano_packet(data, pinfo, subtree)
            local column_info = string.format("#%i %s", chunks_in_packet + 1, payload_type_string[ptype])
            subtree:set_text(column_info)
        end
        position = position + packet_size
        chunks_in_packet = chunks_in_packet + 1
    end
    return chunks_in_packet
end

-- create a function to dissect it
function nano_proto.dissector(tvbuf, pinfo, tree)
    pinfo.cols.protocol = nano_proto.name
    local subtree = tree:add(tvbuf(), nano_proto.name)
    local payload_count = 0

    if ip_proto_f().value == 6 then
        -- TCP
        payload_count = process_nano_tcp(tvbuf, pinfo, subtree)
    else
        -- UDP
        parse_nano_packet(tvbuf, pinfo, subtree)
        payload_count = 1
    end

    if payload_count > 1 then
        pinfo.cols.info = "Multiple payloads"
    end
end

function nano_proto.init()
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol - without specific port binding
udp_table:add(0,nano_proto)
tcp_table:add(0,nano_proto)