-- PackClient Launcher/Core framing, delivery, envelope, and PV10 metadata dissector.

local packclient = Proto("packclient", "PackClient Transport")
local bitlib = bit32 or bit

local f_frame_word = ProtoField.uint32("packclient.frame_word", "Frame word", base.HEX)
local f_body_length = ProtoField.uint32("packclient.body_length", "Body length", base.DEC)
local f_message_type = ProtoField.uint32(
    "packclient.message_type", "Message type", base.HEX,
    {
        [0x01] = "Core type 1",
        [0x02] = "Core type 2",
        [0x03] = "Core structured message",
        [0x0A] = "Core type 10",
        [0x0B] = "Core host inventory",
        [0x11] = "Core type 17",
        [0x12] = "Core PV10 preview",
        [0x15] = "Plaintext delivery",
        [0x16] = "Authenticated encrypted envelope",
    }
)
local f_phase = ProtoField.string("packclient.phase", "Protocol phase")
local f_object_magic = ProtoField.string("packclient.object.magic", "Object magic")
local f_object_version = ProtoField.uint16("packclient.object.version", "Object version", base.DEC)
local f_plh1_field_06 = ProtoField.uint16("packclient.plh1.field_06", "PLH1 field +0x06", base.HEX)
local f_plh1_field_08 = ProtoField.uint32("packclient.plh1.field_08", "PLH1 field +0x08", base.HEX)
local f_plh1_field_0c = ProtoField.uint32("packclient.plh1.field_0c", "PLH1 field +0x0C", base.HEX)
local f_plh1_tick = ProtoField.uint64("packclient.plh1.tick_count_64", "PLH1 tick count", base.DEC)
local f_plh1_pid = ProtoField.uint32("packclient.plh1.process_id", "PLH1 process ID", base.DEC)
local f_plh1_reserved = ProtoField.uint32("packclient.plh1.reserved", "PLH1 reserved", base.HEX)
local f_plc1_field_06 = ProtoField.uint16("packclient.plc1.field_06", "PLC1 field +0x06", base.HEX)
local f_plc1_challenge = ProtoField.bytes("packclient.plc1.challenge", "PLC1 challenge")
local f_pla1_reserved = ProtoField.uint16("packclient.pla1.reserved", "PLA1 reserved", base.HEX)
local f_pla1_authenticator = ProtoField.bytes("packclient.pla1.authenticator", "PLA1 authenticator")
local f_envelope_version = ProtoField.uint8("packclient.envelope.version", "Envelope version", base.DEC)
local f_envelope_iv = ProtoField.bytes("packclient.envelope.iv", "Envelope IV")
local f_envelope_ciphertext_length = ProtoField.uint32(
    "packclient.envelope.ciphertext_length", "Ciphertext length", base.DEC
)
local f_envelope_format = ProtoField.string("packclient.envelope.format", "Envelope format")
local f_envelope_tag = ProtoField.bytes("packclient.envelope.hmac", "Envelope HMAC-SHA-256")
local f_plk1_wire_version = ProtoField.uint16("packclient.plk1.wire_version", "PLK1 wire version", base.DEC)
local f_plk1_lz4_flag = ProtoField.uint8("packclient.plk1.lz4_flag", "PLK1 LZ4 flag", base.HEX)
local f_plk1_reserved = ProtoField.uint8("packclient.plk1.reserved", "PLK1 reserved", base.HEX)
local f_plk1_total_size = ProtoField.uint64("packclient.plk1.total_size", "PLK1 total size", base.DEC)
local f_plk1_original_size = ProtoField.uint64("packclient.plk1.original_size", "PLK1 original size", base.DEC)
local f_plk1_sha256 = ProtoField.bytes("packclient.plk1.expected_sha256", "PLK1 expected plaintext SHA-256")
local f_plk1_chunk_sequence = ProtoField.uint32("packclient.plk1.chunk.sequence", "PLK1 chunk sequence", base.DEC)
local f_plk1_chunk_length = ProtoField.uint32("packclient.plk1.chunk.length", "PLK1 chunk length", base.DEC)
local f_plk1_chunk_data = ProtoField.bytes("packclient.plk1.chunk.data", "PLK1 chunk data")
local f_core_payload = ProtoField.bytes("packclient.core.payload", "Core payload")
local f_core_command = ProtoField.string("packclient.core.command", "Core command text")
local f_pv10_magic = ProtoField.string("packclient.pv10.magic", "PV10 magic")
local f_pv10_jpeg_length = ProtoField.uint32("packclient.pv10.jpeg_length", "PV10 JPEG length", base.DEC)
local f_pv10_jpeg = ProtoField.bytes("packclient.pv10.jpeg", "PV10 JPEG data")
local ex_malformed_framing = ProtoExpert.new(
    "packclient.expert.malformed_framing", "Malformed PackClient framing",
    expert.group.MALFORMED, expert.severity.ERROR
)
local ex_malformed_object = ProtoExpert.new(
    "packclient.expert.malformed_object", "Malformed PackClient object",
    expert.group.MALFORMED, expert.severity.ERROR
)
local ex_malformed_envelope = ProtoExpert.new(
    "packclient.expert.malformed_envelope", "Malformed PackClient type 0x16 envelope",
    expert.group.MALFORMED, expert.severity.ERROR
)
local ex_malformed_pv10 = ProtoExpert.new(
    "packclient.expert.malformed_pv10", "Malformed Core PV10 preview",
    expert.group.MALFORMED, expert.severity.ERROR
)

packclient.fields = {
    f_frame_word, f_body_length, f_message_type, f_phase, f_object_magic, f_object_version,
    f_plh1_field_06, f_plh1_field_08, f_plh1_field_0c, f_plh1_tick,
    f_plh1_pid, f_plh1_reserved, f_plc1_field_06, f_plc1_challenge,
    f_pla1_reserved, f_pla1_authenticator, f_envelope_version, f_envelope_iv,
    f_envelope_ciphertext_length, f_envelope_format, f_envelope_tag, f_plk1_wire_version,
    f_plk1_lz4_flag, f_plk1_reserved, f_plk1_total_size,
    f_plk1_original_size, f_plk1_sha256, f_plk1_chunk_sequence,
    f_plk1_chunk_length, f_plk1_chunk_data, f_core_payload, f_core_command,
    f_pv10_magic, f_pv10_jpeg_length, f_pv10_jpeg,
}
packclient.experts = {
    ex_malformed_framing, ex_malformed_object, ex_malformed_envelope,
    ex_malformed_pv10,
}

local FRAME_PREFIX = 0x5A400000
local FRAME_PREFIX_MASK = 0xFFC00000
local BODY_LENGTH_MASK = 0x003FFFFF
local KNOWN_PLAINTEXT_BODY_LENGTHS = {
    [36] = true, -- type DWORD + PLH1 (32)
    [28] = true, -- type DWORD + PLC1 (24)
    [44] = true, -- type DWORD + PLA1 (40)
    [60] = true, -- type DWORD + PLK1 (56)
}
local EXPECTED_BODY_BY_MAGIC = {
    PLH1 = 36,
    PLC1 = 28,
    PLA1 = 44,
    PLK1 = 60,
}

local function valid_frame_word(word)
    return bitlib.band(word, FRAME_PREFIX_MASK) == FRAME_PREFIX
end

local function get_pdu_length(tvb, pinfo, offset)
    local word = tvb(offset, 4):le_uint()
    if not valid_frame_word(word) then
        return 4
    end
    return 4 + bitlib.band(word, BODY_LENGTH_MASK)
end

local function add_handshake_or_plk1(tvb, subtree, body_length)
    local payload_length = body_length - 4
    if payload_length < 4 then
        return nil
    end
    local magic = tvb(8, 4):string()
    if magic == "PLH1" and payload_length == 32 then
        local version = tvb(12, 2):le_uint()
        local field_06 = tvb(14, 2):le_uint()
        local field_08 = tvb(16, 4):le_uint()
        local field_0c = tvb(20, 4):le_uint()
        local reserved = tvb(36, 4):le_uint()
        if version ~= 1 or field_06 ~= 0x20 or field_08 ~= 0 or
                field_0c ~= 1 or reserved ~= 0 then
            return nil, "PLH1 fixed field validation failed"
        end
        subtree:add(f_object_magic, tvb(8, 4))
        subtree:add_le(f_object_version, tvb(12, 2))
        subtree:add_le(f_plh1_field_06, tvb(14, 2))
        subtree:add_le(f_plh1_field_08, tvb(16, 4))
        subtree:add_le(f_plh1_field_0c, tvb(20, 4))
        subtree:add_le(f_plh1_tick, tvb(24, 8))
        subtree:add_le(f_plh1_pid, tvb(32, 4))
        subtree:add_le(f_plh1_reserved, tvb(36, 4))
        return "PLH1"
    elseif magic == "PLC1" and payload_length == 24 then
        if tvb(12, 2):le_uint() ~= 1 then
            return nil, "PLC1 version must be 1"
        end
        subtree:add(f_object_magic, tvb(8, 4))
        subtree:add_le(f_object_version, tvb(12, 2))
        subtree:add_le(f_plc1_field_06, tvb(14, 2))
        subtree:add(f_plc1_challenge, tvb(16, 16))
        return "PLC1"
    elseif magic == "PLA1" and payload_length == 40 then
        if tvb(12, 2):le_uint() ~= 1 or tvb(14, 2):le_uint() ~= 0 then
            return nil, "PLA1 fixed field validation failed"
        end
        subtree:add(f_object_magic, tvb(8, 4))
        subtree:add_le(f_object_version, tvb(12, 2))
        subtree:add_le(f_pla1_reserved, tvb(14, 2))
        subtree:add(f_pla1_authenticator, tvb(16, 32))
        return "PLA1"
    elseif magic == "PLK1" and payload_length == 56 then
        local wire_version = tvb(12, 2):le_uint()
        local total_size = tvb(16, 8):le_uint64():tonumber()
        local original_size = tvb(24, 8):le_uint64():tonumber()
        if wire_version ~= 1 and wire_version ~= 2 then
            return nil, "PLK1 wire version must be 1 or 2"
        end
        if total_size == 0 or total_size > 0x08000000 then
            return nil, "PLK1 total size is outside 1..0x08000000"
        end
        if wire_version == 2 and (original_size == 0 or original_size > 0x08000000) then
            return nil, "PLK1 original size is outside 1..0x08000000"
        end
        subtree:add(f_object_magic, tvb(8, 4))
        subtree:add_le(f_plk1_wire_version, tvb(12, 2))
        subtree:add(f_plk1_lz4_flag, tvb(14, 1))
        subtree:add(f_plk1_reserved, tvb(15, 1))
        subtree:add_le(f_plk1_total_size, tvb(16, 8))
        subtree:add_le(f_plk1_original_size, tvb(24, 8))
        subtree:add(f_plk1_sha256, tvb(32, 32))
        return "PLK1"
    elseif magic == "PLH1" or magic == "PLC1" or magic == "PLA1" or magic == "PLK1" then
        return nil, magic .. " has an invalid payload length"
    end
    if payload_length >= 8 then
        local data_length = tvb(12, 4):le_uint()
        if data_length == payload_length - 8 then
            local sequence = tvb(8, 4):le_uint()
            subtree:add_le(f_plk1_chunk_sequence, tvb(8, 4))
            subtree:add_le(f_plk1_chunk_length, tvb(12, 4))
            if data_length > 0 then
                subtree:add(f_plk1_chunk_data, tvb(16, data_length))
            end
            return "PLK1 chunk " .. sequence
        end
    end
    return nil, nil
end

local function add_envelope_metadata(tvb, subtree, body_length)
    local envelope_length = body_length - 4
    if envelope_length < 0x35 then
        return nil, "type 0x16 envelope is shorter than 0x35 bytes"
    end
    local version = tvb(8, 1):uint()
    local ciphertext_length_be = tvb(25, 4):uint()
    local ciphertext_length_le = tvb(25, 4):le_uint()
    local expected_ciphertext_length = envelope_length - 0x35
    local launcher_format = ciphertext_length_be == expected_ciphertext_length
    local core_format = ciphertext_length_le == expected_ciphertext_length
    local ciphertext_length = nil
    local format = nil
    if launcher_format and not core_format then
        ciphertext_length = ciphertext_length_be
        format = "Launcher (big-endian length)"
    elseif core_format and not launcher_format then
        ciphertext_length = ciphertext_length_le
        format = "Core (little-endian length)"
    elseif launcher_format and core_format then
        ciphertext_length = ciphertext_length_be
        format = "Ambiguous byte order"
    end
    subtree:add(f_envelope_version, tvb(8, 1))
    subtree:add(f_envelope_iv, tvb(9, 16))
    if version ~= 1 then
        return nil, "type 0x16 envelope version must be 1"
    end
    if ciphertext_length == nil then
        return nil, "type 0x16 envelope length does not match its ciphertext length"
    end
    if core_format and not launcher_format then
        subtree:add_le(f_envelope_ciphertext_length, tvb(25, 4))
    else
        subtree:add(f_envelope_ciphertext_length, tvb(25, 4))
    end
    subtree:add(f_envelope_format, format)
    if ciphertext_length == 0 then
        return nil, "type 0x16 ciphertext is empty"
    end
    if ciphertext_length % 16 ~= 0 then
        return nil, "type 0x16 ciphertext length is not AES block-aligned"
    end
    subtree:add(f_envelope_tag, tvb(29 + ciphertext_length, 32))
    return format .. " envelope metadata", nil
end

local CORE_COMMAND_PREFIXES = {"INP|", "SYS|", "TLM|", "SCR|", "Q|", "PIPE|"}

local function find_core_command(tvb, payload_length)
    if payload_length == 0 then
        return nil, nil
    end
    local raw = tvb(8, payload_length):string()
    local first = nil
    for _, marker in ipairs(CORE_COMMAND_PREFIXES) do
        local position = string.find(raw, marker, 1, true)
        if position and (first == nil or position < first) then
            first = position
        end
    end
    if first == nil then
        return nil, nil
    end
    local ending = string.find(raw, "\0", first, true)
    local length = (ending and ending - first) or (#raw - first + 1)
    return first - 1, length
end

local function add_core_metadata(tvb, subtree, message_type, body_length)
    local payload_length = body_length - 4
    subtree:add(f_phase, "Core")
    if payload_length > 0 then
        subtree:add(f_core_payload, tvb(8, payload_length))
    end
    if message_type == 0x12 then
        if payload_length < 8 then
            return nil, "PV10 payload is shorter than 8 bytes"
        end
        if tvb(8, 4):string() ~= "PV10" then
            return nil, "Core type 18 payload does not begin with PV10"
        end
        local jpeg_length = tvb(12, 4):le_uint()
        subtree:add(f_pv10_magic, tvb(8, 4))
        subtree:add_le(f_pv10_jpeg_length, tvb(12, 4))
        if jpeg_length ~= payload_length - 8 then
            return nil, "PV10 JPEG length does not match the payload"
        end
        if jpeg_length < 2 or tvb(16, 2):uint() ~= 0xFFD8 then
            return nil, "PV10 data does not begin with a JPEG SOI marker"
        end
        if jpeg_length < 4 or tvb(16 + jpeg_length - 2, 2):uint() ~= 0xFFD9 then
            return nil, "PV10 data does not end with a JPEG EOI marker"
        end
        subtree:add(f_pv10_jpeg, tvb(16, jpeg_length))
        return "Core PV10 JPEG (" .. jpeg_length .. " bytes)", nil
    end
    local command_offset, command_length = find_core_command(tvb, payload_length)
    if command_offset then
        subtree:add(f_core_command, tvb(8 + command_offset, command_length))
    end
    return "Core type " .. message_type, nil
end

local function dissect_pdu(tvb, pinfo, tree)
    local frame_word = tvb(0, 4):le_uint()
    local body_length = bitlib.band(frame_word, BODY_LENGTH_MASK)
    local subtree = tree:add(packclient, tvb(), "PackClient Transport")
    subtree:add_le(f_frame_word, tvb(0, 4))
    subtree:add(f_body_length, tvb(0, 4), body_length)
    if not valid_frame_word(frame_word) or body_length < 4 or tvb:len() ~= 4 + body_length then
        subtree:append_text(" (malformed framing)")
        subtree:add_proto_expert_info(ex_malformed_framing)
        pinfo.cols.protocol = "PackClient"
        return tvb:len()
    end
    local message_type = tvb(4, 4):le_uint()
    subtree:add_le(f_message_type, tvb(4, 4))
    local classification = nil
    local validation_error = nil
    if message_type == 0x15 then
        classification, validation_error = add_handshake_or_plk1(tvb, subtree, body_length)
        if classification then
            subtree:add(f_phase, "Launcher")
        end
        if validation_error then
            subtree:add_proto_expert_info(ex_malformed_object, validation_error)
        end
    elseif message_type == 0x16 then
        classification, validation_error = add_envelope_metadata(tvb, subtree, body_length)
        if classification then
            if string.sub(classification, 1, 4) == "Core" then
                subtree:add(f_phase, "Core")
            elseif string.sub(classification, 1, 8) == "Launcher" then
                subtree:add(f_phase, "Launcher")
            end
        end
        if validation_error then
            subtree:add_proto_expert_info(ex_malformed_envelope, validation_error)
        end
    elseif message_type == 0x01 or message_type == 0x02 or message_type == 0x03 or
            message_type == 0x0A or message_type == 0x0B or
            message_type == 0x11 or message_type == 0x12 then
        classification, validation_error = add_core_metadata(tvb, subtree, message_type, body_length)
        if validation_error then
            subtree:add_proto_expert_info(ex_malformed_pv10, validation_error)
        end
    end
    pinfo.cols.protocol = "PackClient"
    if classification then
        pinfo.cols.info:append(" " .. classification)
        subtree:append_text(" (" .. classification .. ")")
    end
    return tvb:len()
end

local function dissect_stream(tvb, pinfo, tree)
    dissect_tcp_pdus(tvb, tree, 4, get_pdu_length, dissect_pdu, true)
    return tvb:len()
end

function packclient.dissector(tvb, pinfo, tree)
    return dissect_stream(tvb, pinfo, tree)
end

local function valid_heuristic_start(tvb)
    if tvb:len() < 4 then
        return false
    end
    local word = tvb(0, 4):le_uint()
    if not valid_frame_word(word) then
        return false
    end
    local body_length = bitlib.band(word, BODY_LENGTH_MASK)
    if body_length < 4 then
        return false
    end

    -- Claim a four-byte split only when its declared size matches a known
    -- fixed-size plaintext object. This permits desegmentation without accepting
    -- the frame prefix alone.
    if tvb:len() < 8 then
        return KNOWN_PLAINTEXT_BODY_LENGTHS[body_length] == true
    end

    local message_type = tvb(4, 4):le_uint()
    if message_type == 0x15 then
        if not KNOWN_PLAINTEXT_BODY_LENGTHS[body_length] then
            return false
        end
        if tvb:len() < 12 then
            return true
        end
        local magic = tvb(8, 4):string()
        if EXPECTED_BODY_BY_MAGIC[magic] ~= body_length then
            return false
        end
        if tvb:len() < 4 + body_length then
            return true
        end
        if magic == "PLH1" then
            return tvb(12, 2):le_uint() == 1 and
                tvb(14, 2):le_uint() == 0x20 and
                tvb(16, 4):le_uint() == 0 and
                tvb(20, 4):le_uint() == 1 and
                tvb(36, 4):le_uint() == 0
        elseif magic == "PLC1" then
            return tvb(12, 2):le_uint() == 1
        elseif magic == "PLA1" then
            return tvb(12, 2):le_uint() == 1 and tvb(14, 2):le_uint() == 0
        elseif magic == "PLK1" then
            local wire_version = tvb(12, 2):le_uint()
            local total_size = tvb(16, 8):le_uint64():tonumber()
            local original_size = tvb(24, 8):le_uint64():tonumber()
            if wire_version ~= 1 and wire_version ~= 2 then
                return false
            end
            if total_size == 0 or total_size > 0x08000000 then
                return false
            end
            return wire_version == 1 or (original_size > 0 and original_size <= 0x08000000)
        end
        return false
    elseif message_type == 0x16 then
        local envelope_length = body_length - 4
        if envelope_length < 0x35 or tvb:len() < 29 then
            return false
        end
        local expected = envelope_length - 0x35
        return tvb(8, 1):uint() == 1 and
            (tvb(25, 4):uint() == expected or tvb(25, 4):le_uint() == expected)
    elseif message_type == 0x03 then
        local payload_length = body_length - 4
        if payload_length == 0 or tvb:len() < 4 + body_length then
            return false
        end
        local command_offset = find_core_command(tvb, payload_length)
        return command_offset ~= nil
    elseif message_type == 0x12 then
        local payload_length = body_length - 4
        if payload_length < 10 or tvb:len() < 4 + body_length then
            return false
        end
        return tvb(8, 4):string() == "PV10" and
            tvb(12, 4):le_uint() == payload_length - 8 and
            tvb(16, 2):uint() == 0xFFD8 and
            tvb(16 + payload_length - 8 - 2, 2):uint() == 0xFFD9
    end
    return false
end

packclient:register_heuristic("tcp", function(tvb, pinfo, tree)
    if not valid_heuristic_start(tvb) then
        return false
    end
    dissect_stream(tvb, pinfo, tree)
    return true
end)

-- Decode As supports split, mid-stream, and otherwise ambiguous captures.
DissectorTable.get("tcp.port"):add_for_decode_as(packclient)
