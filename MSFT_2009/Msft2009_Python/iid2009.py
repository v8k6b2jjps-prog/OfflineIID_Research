#!/usr/bin/env python

import math
import hashlib
import argparse

class BinaryKey:
    CrcTable = (
        0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
        0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
        0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75,
        0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD,
        0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5,
        0xBE2B5B58, 0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D,
        0xD4326D90, 0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
        0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D,
        0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072,
        0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA,
        0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02,
        0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1, 0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
        0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692,
        0x8AAD2B2F, 0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
        0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2,
        0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34, 0xDC3ABDED, 0xD8FBA05A,
        0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
        0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53,
        0x251D3B9E, 0x21DC2629, 0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B,
        0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623,
        0xF12F560E, 0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B,
        0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
        0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B,
        0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3,
        0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640, 0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C,
        0x7B827D21, 0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24,
        0x119B4BE9, 0x155A565E, 0x18197087, 0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
        0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
        0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB, 0xDBEE767C,
        0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4,
        0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C,
        0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4
    )

    def __init__(self, *args):
        self.Group = 0
        self.Serial = 0
        self.Security = 0
        self.IsNKey = False
        self.Checksum = 0
        self.BinaryData = b""
        self.CdKey = ""

        if len(args) == 1:
            arg = args[0]
            if isinstance(arg, str):
                self.BinaryData = self.encode_binary_key(arg)
                info = self.unpack_binary_key(self.BinaryData, True)
                self.Group = info["Group"]
                self.Serial = info["Serial"]
                self.Security = info["Security"]
                self.IsNKey = info["IsNKey"]
                self.CdKey = arg
                self.Checksum = self.get_key_checksum(self.BinaryData)
            elif isinstance(arg, (bytes, bytearray)):
                self.BinaryData = bytes(arg)
                info = self.unpack_binary_key(self.BinaryData, True)
                self.Group = info["Group"]
                self.Serial = info["Serial"]
                self.Security = info["Security"]
                self.IsNKey = info["IsNKey"]
                self.CdKey = self.decode_binary_key(self.BinaryData)
                self.Checksum = self.get_key_checksum(self.BinaryData)
        elif len(args) >= 3:
            self.Group = args[0]
            self.Serial = args[1]
            self.Security = args[2]
            self.IsNKey = args[3] if len(args) > 3 else True
            stream = args[4] if len(args) > 4 else True
            self.BinaryData = self.format_binary_key(self.Group, self.Serial, self.Security, self.IsNKey, stream)
            self.CdKey = self.decode_binary_key(self.BinaryData)
            self.Checksum = self.get_key_checksum(self.BinaryData)

    @staticmethod
    def get_key_checksum(data: bytes) -> int:
        v35 = bytearray(data)
        v11 = v35[14]
        is_n_key_set = (v11 & 8) != 0
        v14 = v11 ^ ((v11 ^ (4 * int(is_n_key_set))) & 8)
        v35[12] = v35[12] & 0x7F
        v17 = v14 & 0xFE
        v35[14] = v17
        v35[13] = 0

        v20 = 0xFFFFFFFF
        for b in v35:
            idx = (b ^ (v20 >> 24)) & 0xFF
            v20 = ((v20 << 8) ^ BinaryKey.CrcTable[idx]) & 0xFFFFFFFF

        final_crc = (~v20) & 0x3FF
        return final_crc

    @staticmethod
    def _set_bits(data: bytearray, start_bit: int, value: int, count: int):
        byte_offset = start_bit >> 3
        bit_offset = start_bit & 7

        chunk_bytes = bytearray(8)
        bytes_to_copy = min(8, len(data) - byte_offset)
        chunk_bytes[:bytes_to_copy] = data[byte_offset:byte_offset + bytes_to_copy]
        current_data = int.from_bytes(chunk_bytes, 'little')

        mask = (1 << count) - 1
        if count == 64:
            mask = 0xFFFFFFFFFFFFFFFF
        cleared_mask = ~(mask << bit_offset) & 0xFFFFFFFFFFFFFFFF

        new_data = (current_data & cleared_mask) | ((value & mask) << bit_offset)
        modified_bytes = new_data.to_bytes(8, 'little')
        data[byte_offset:byte_offset + bytes_to_copy] = modified_bytes[:bytes_to_copy]

    @staticmethod
    def _get_bits(data: bytes, start_bit: int, count: int) -> int:
        byte_offset = start_bit >> 3
        bit_offset = start_bit & 7

        chunk_bytes = bytearray(8)
        bytes_to_copy = min(8, len(data) - byte_offset)
        chunk_bytes[:bytes_to_copy] = data[byte_offset:byte_offset + bytes_to_copy]
        u64 = int.from_bytes(chunk_bytes, 'little')

        mask = (1 << count) - 1
        if count == 64:
            mask = 0xFFFFFFFFFFFFFFFF
        return (u64 >> bit_offset) & mask

    @staticmethod
    def format_binary_key(group: int, serial: int, security: int, is_n_key: bool = True, stream: bool = True) -> bytes:
        if stream:
            key = 0
            key |= group
            key |= (serial & 0x3FFFFFFF) << 20
            key |= (security & 0x1FFFFFFFFFFFFF) << 50

            if is_n_key:
                key |= 1 << 115

            binary_data_ = bytearray(key.to_bytes(16, 'little') if key > 0 else 16)
            if len(binary_data_) < 16:
                binary_data_.extend([0] * (16 - len(binary_data_)))
            binary_data_ = bytearray(binary_data_[:16])

            crc = BinaryKey.get_key_checksum(binary_data_)
            if crc & 0x01:
                binary_data_[12] |= 0x80
            binary_data_[13] = (crc >> 1) & 0xFF
            if crc & 0x200:
                binary_data_[14] |= 0x01
        else:
            SERIAL_OFFSET = 20
            SERIAL_BITS = 30
            SECURITY_OFFSET = 50
            SECURITY_BITS = 53

            binary_data_ = bytearray(16)
            binary_data_[0:2] = group.to_bytes(2, 'little')
            BinaryKey._set_bits(binary_data_, SERIAL_OFFSET, serial, SERIAL_BITS)
            BinaryKey._set_bits(binary_data_, SECURITY_OFFSET, security, SECURITY_BITS)

            if is_n_key:
                binary_data_[14] |= 0x08

            crc = BinaryKey.get_key_checksum(binary_data_)
            if crc & 0x001:
                binary_data_[12] |= 0x80
            binary_data_[13] = (crc >> 1) & 0xFF
            if crc & 0x200:
                binary_data_[14] |= 0x01

        return bytes(binary_data_)

    @staticmethod
    def unpack_binary_key(binary_data: bytes, stream: bool = True) -> dict:
        if stream:
            temp_bytes = bytearray(binary_data[:16])
            temp_bytes.append(0)
            value = int.from_bytes(temp_bytes, 'little')

            return {
                "Group": value & 0xFFFF,
                "Serial": (value >> 20) & 0x3FFFFFFF,
                "Security": (value >> 50) & 0x1FFFFFFFFFFFFF,
                "IsNKey": ((value >> 115) & 1) == 1,
                "Checksum": BinaryKey.get_key_checksum(binary_data)
            }
        else:
            SERIAL_OFFSET = 20
            SERIAL_BITS = 30
            SECURITY_OFFSET = 50
            SECURITY_BITS = 53

            return {
                "Group": int.from_bytes(binary_data[0:2], 'little'),
                "Serial": BinaryKey._get_bits(binary_data, SERIAL_OFFSET, SERIAL_BITS),
                "Security": BinaryKey._get_bits(binary_data, SECURITY_OFFSET, SECURITY_BITS),
                "IsNKey": (binary_data[14] & 0x08) != 0
            }

    @staticmethod
    def encode_binary_key(cd_key: str) -> bytes:
        alphabet = "BCDFGHJKMPQRTVWXY2346789"
        raw_key = cd_key.replace("-", "").upper()
        if len(raw_key) != 25:
            raise ValueError("Key must be 25 characters.")

        digits = bytearray(25)
        is_n_key_ = False
        digit_count = 0

        for char in raw_key:
            if char == 'N' and not is_n_key_:
                is_n_key_ = True
                for i in range(digit_count, 0, -1):
                    digits[i] = digits[i-1]
                digits[0] = digit_count
                digit_count += 1
                continue
            val = alphabet.find(char)
            if val < 0:
                raise ValueError(f"Invalid character in key: {char}")
            digits[digit_count] = val
            digit_count += 1

        binary = bytearray(16)
        for digit in digits:
            carry = digit
            for i in range(16):
                res = (binary[i] * 24) + carry
                binary[i] = res & 0xFF
                carry = res >> 8

        if is_n_key_:
            binary[14] |= 0x08
        return bytes(binary)

    @staticmethod
    def decode_binary_key(b_cd_key_array: bytes) -> str:
        last = 0
        key_data = bytearray(b_cd_key_array)
        src = [''] * 27
        charset = "BCDFGHJKMPQRTVWXY2346789"

        if len(key_data) < 15 or len(key_data) > 16:
            raise ValueError("Input data must be a 15 or 16 byte array.")

        if (key_data[14] & 0xF0) != 0:
            raise ValueError("Failed to decode key!")

        byte14 = key_data[14]
        flag = (byte14 & 0x08) != 0

        key_data[14] = (4 * ((1 if (byte14 & 8) != 0 else 0) & 2)) | (byte14 & 0xF7)

        for idx in range(24, -1, -1):
            last = 0
            for j in range(14, -1, -1):
                val = key_data[j] + (last << 8)
                key_data[j] = val // 0x18
                last = val % 0x18
            src[idx] = charset[last]

        if key_data[0] != 0:
            raise ValueError("Invalid product key data")

        rev = last > 13
        pos = 25 if rev else -1
        t = 0

        if flag:
            if last <= 0:
                src[0] = 'N'
            elif rev:
                while pos > last:
                    src[pos] = src[pos - 1]
                    pos -= 1
                t = 1
                src[last + 1] = 'N'
            else:
                while True:
                    pos += 1
                    if pos >= last:
                        break
                    src[pos] = src[pos + 1]
                src[last] = 'N'

        output_parts = []
        for i in range(5):
            start = (5 * i) + t
            end = (5 * i) + 4 + t + 1
            output_parts.append("".join(src[start:end]))

        return "-".join(output_parts)

def get_default_context():
    constants = [
        0x84D8F8F0D45EC86B, 0xF413937D2F2A4177,
        0xBB9515A2E6668A1B, 0x972B328367B09D0E,
        0xEEDC7D7CCDD9FE49, 0xEB3B0BE7DF1207B0,
        0xCFA627FDDF98BD56, 0x573A73F8C236845D
    ]
    round_keys = []
    for val in constants:
        round_keys.append(val & 0xFFFFFFFF)
        round_keys.append((val >> 32) & 0xFFFFFFFF)
    return round_keys

def run_round_hash(block, round_key, bit_len):
    hasher = hashlib.sha1()
    hasher.update(b"\x79")
    hasher.update(block)
    hasher.update(round_key.to_bytes(4, "little"))
    digest = hasher.digest()
    
    byte_count = (bit_len + 31) >> 5
    output_hash = bytearray(digest[:4 * byte_count])
    
    if byte_count > 0:
        last_index = 4 * (byte_count - 1)
        last_dword = int.from_bytes(output_hash[last_index:last_index+4], "little")
        last_dword >>= (32 * byte_count - bit_len)
        output_hash[last_index:last_index+4] = last_dword.to_bytes(4, "little")
        
    return bytes(output_hash)

def encryption_context_process(size, data, decrypt=False):
    half_size = size // 2
    round_keys = get_default_context()
    
    left = bytearray(data[:half_size])
    right = bytearray(data[half_size:])
    bit_len = 8 * half_size
    
    if not decrypt:
        for round_idx in range(16):
            round_hash_out = run_round_hash(bytes(right), round_keys[round_idx], bit_len)
            temp = bytearray(right)
            for i in range(half_size):
                right[i] = left[i] ^ round_hash_out[i]
                left[i] = temp[i]
    else:
        for round_idx in range(15, -1, -1):
            round_hash_out = run_round_hash(bytes(left), round_keys[round_idx], bit_len)
            for i in range(half_size):
                old_left = right[i] ^ round_hash_out[i]
                old_right = left[i]
                left[i] = old_left
                right[i] = old_right
                
    return bytes(left + right)

def decimal_string_to_binary(decimal_str, byte_count):
    val = int(decimal_str)
    # Match C#'s little-endian output by reversing the big-endian bytes
    buffer = bytearray(val.to_bytes(byte_count, "big"))
    buffer.reverse()
    return bytes(buffer)

def binary_to_decimal_string(src, bit_count):
    v11 = math.log10(2.0)
    v12 = v11 * bit_count / math.log10(10.0)  # Fixed parameter name
    digitCount = int(v12) + 1
    if v12 <= int(v12):
        digitCount = int(v12)
    if digitCount <= 0:
        return ""

    buffer = bytearray(src)
    v5 = len(buffer)
    result_chars = ['0'] * digitCount

    v13 = digitCount
    v16 = v5 - 1

    while v13 > 0:
        v13 -= 1
        remainder = 0
        if v16 >= 0:
            currentIndex = v16
            innerCount = v5
            while innerCount > 0:
                current = buffer[currentIndex] + (remainder << 8)
                buffer[currentIndex] = current // 10
                remainder = current % 10
                currentIndex -= 1
                innerCount -= 1
        result_chars[v13] = chr(ord('0') + remainder)

    return "".join(result_chars)

def format_installation_id(raw_digits):
    raw_digits = raw_digits.zfill(54)  # Ensure proper length formatting padding
    formatted = []
    total_len = len(raw_digits)
    group_size = 6
    group_count = (total_len + group_size - 1) // group_size

    for g in range(group_count):
        start = g * group_size
        length = min(group_size, total_len - start)
        weighted_sum = 0
        group_chars = []

        for i in range(length):
            c = raw_digits[start + i]
            digit = int(c)
            weighted_sum += 2 * digit if (i % 2 != 0) else digit
            group_chars.append(c)

        check_digit = weighted_sum % 7
        formatted.append("".join(group_chars) + str(check_digit))

    return "".join(formatted)

def strip_check_digits(formatted_iid):
    raw = []
    for i, ch in enumerate(formatted_iid):
        if ((i + 1) % 7) != 0:
            raw.append(ch)
    return "".join(raw)

def unshift_block(shifted):
    if len(shifted) != 23:
        raise Exception(f"Expected 23-byte shifted block, got {len(shifted)}")
    cipher = bytearray(22)
    for i in range(22):
        cipher[i] = (shifted[i] >> 3) | ((shifted[i + 1] & 0x07) << 5)
    return bytes(cipher)

def shift_block(out_cipher_block):
    shifted_block = bytearray(23)
    for i in range(22):
        v40 = out_cipher_block[i]
        v41 = shifted_block[i]
        shifted_block[i + 1] = (shifted_block[i + 1] & 0xF8) | (v40 >> 5)
        shifted_block[i] = (v41 & 0x07) | ((v40 << 3) & 0xFF)
    return bytes(shifted_block)

def build_and_encrypt_cipher_block(group_id, serial, security_id, hwid):
    pkey_data = bytearray(88)
    pkey_data[16:20] = group_id.to_bytes(4, "little")
    pkey_data[24:28] = serial.to_bytes(4, "little")
    pkey_data[32:40] = security_id.to_bytes(8, "little")

    out_cipher_block = bytearray(22)
    v6 = pkey_data[37]
    v9 = int.from_bytes(pkey_data[32:34], "little")

    out_cipher_block[0:2] = v9.to_bytes(2, "little")
    out_cipher_block[2] = pkey_data[34]
    v9_low = pkey_data[35] & 0x0F
    out_cipher_block[3] = ((16 * v6) | (v9_low & 0x0F)) & 0xFF  # Fixed

    v13 = pkey_data[38] >> 4
    out_cipher_block[4] = ((v6 >> 4) | (16 * pkey_data[38])) & 0xFF  # Fixed
    out_cipher_block[5] = (v13 & 1) & 0xFF

    v7_offset = 16
    v14_idx = 5
    v12_idx = 6
    v11 = 2
    while v11 > 0:
        src_idx = v7_offset + (v14_idx - 5)
        v16 = pkey_data[src_idx]
        out_cipher_block[v14_idx] = (out_cipher_block[v14_idx] & 1) | ((2 * v16) & 0xFF)
        out_cipher_block[v12_idx] = (out_cipher_block[v12_idx] & ~1) | ((v16 >> 7) & 0xFF)
        v14_idx += 1
        v12_idx += 1
        v11 -= 1

    v18 = int.from_bytes(pkey_data[20:24], "little")
    out_cipher_block[7] = (out_cipher_block[7] ^ ((out_cipher_block[7] ^ (2 * pkey_data[18])) & 0x1E)) & 0xFF

    v5 = 1000000 * v18 if v18 != 0 else 0
    serial_val = int.from_bytes(pkey_data[24:28], "little")
    var50 = v5 + serial_val

    var50_bytes = var50.to_bytes(4, "little")
    v21 = 0
    v22_idx = 8
    v23 = 3
    while v23 > 0:
        v24_val = var50_bytes[v21]
        v25 = out_cipher_block[v21 + 7]
        out_cipher_block[v22_idx] = (out_cipher_block[v22_idx] & 0xE0) | (v24_val >> 3)
        out_cipher_block[v21 + 7] = ((v25 & 0x1F) | (32 * v24_val)) & 0xFF
        v21 += 1
        v22_idx += 1
        v23 -= 1

    byte3_v50 = var50 >> 24
    out_cipher_block[10] = ((32 * byte3_v50) | (out_cipher_block[10] & 0x1F)) & 0xFF
    seq_val = int.from_bytes(pkey_data[28:32], "little")
    out_cipher_block[11] = ((8 if seq_val != 0 else 0) | ((out_cipher_block[11] & 0xF0) ^ ((byte3_v50 >> 3) & 7))) & 0xFF

    hwid_bytes = hwid.to_bytes(8, "little", signed=True)
    v26_idx = 12
    v27 = 8
    v28_idx = 0
    while v27 > 0:
        v29 = hwid_bytes[v28_idx]
        v30 = out_cipher_block[v28_idx + 11]
        out_cipher_block[v26_idx] = (out_cipher_block[v26_idx] & 0xF0) | (v29 >> 4)
        out_cipher_block[v28_idx + 11] = ((v30 & 0x0F) | (16 * v29)) & 0xFF
        v28_idx += 1
        v26_idx += 1
        v27 -= 1

    encrypted_cipher = encryption_context_process(22, bytes(out_cipher_block), decrypt=False)
    shifted_block = shift_block(encrypted_cipher)
    return shifted_block
    
def read_back_parameters(plaintext22):
    # 1. Recover lower bits (0-27)
    sec_id_low = int.from_bytes(plaintext22[0:2], "little")
    sec_id_byte2 = plaintext22[2]
    sec_id_nibble = plaintext22[3] & 0x0F
    
    security_id_recovered = sec_id_low | (sec_id_byte2 << 16) | (sec_id_nibble << 24)

    # 2. Recover upper surviving bits (Bits 40+) with correct nibble assembly
    nibble_low = plaintext22[3] >> 4         # bits 40-43
    nibble_mid = plaintext22[4] & 0x0F       # bits 44-47
    nibble_high = plaintext22[4] >> 4        # bits 48-51

    upper_val = nibble_low | (nibble_mid << 4) | (nibble_high << 8)
    security_id_recovered |= (upper_val << 40)

    # Bit 52 is stored in bit 0 of plaintext22[5] (shares a byte with group id)
    security_id_recovered |= (plaintext22[5] & 1) << 52

    # --- Group ID ---
    group_id_bytes = bytearray(2)
    for i in range(2):
        group_id_bytes[i] = (plaintext22[5 + i] >> 1) | ((plaintext22[6 + i] & 0x01) << 7)
    group_id = int.from_bytes(group_id_bytes, "little")
    group_id |= ((plaintext22[7] >> 1) & 0x0F) << 16

    # --- Serial / var50 ---
    var50_bytes = bytearray(4)
    for i in range(3):
        var50_bytes[i] = (plaintext22[7 + i] >> 5) | ((plaintext22[8 + i] & 0x1F) << 3)

    byte3_high = plaintext22[10] >> 5
    byte3_low = (plaintext22[11] & 0x07) << 3
    var50_bytes[3] = byte3_high | byte3_low
    serial = int.from_bytes(var50_bytes, "little")

    # --- HWID ---
    hwid_bytes = bytearray(8)
    for i in range(8):
        high = (plaintext22[12 + i] & 0x0F) << 4
        low = plaintext22[11 + i] >> 4
        hwid_bytes[i] = high | low
    hwid = int.from_bytes(hwid_bytes, "little", signed=True)

    return security_id_recovered, group_id, serial, hwid

def format_security_id_with_gap(security_id):
    """Formats the 64-bit security ID in hex, replacing the 12-bit gap (bits 28-39) with '???'."""
    hex_str = f"{security_id:016x}"
    # 64 bits = 16 hex chars. 
    # Bits 0-27 = last 7 chars. Bits 28-39 = next 3 chars. Bits 40-63 = first 6 chars.
    upper_part = hex_str[:-10]  # chars 0 to 5 (bits 40-63)
    gap = "???"                # chars 6 to 8 (bits 28-39)
    lower_part = hex_str[-7:]  # chars 9 to 15 (bits 0-27)
    return "0x" + (upper_part + gap + lower_part).lstrip("0")

def encode_iid(group_id, serial, security_id, hwid):
    cipher_block = build_and_encrypt_cipher_block(group_id, serial, security_id, hwid)
    raw_decimal = binary_to_decimal_string(cipher_block, 179)
    return format_installation_id(raw_decimal)

def decode_iid(formatted_iid):
    raw_digits = strip_check_digits(formatted_iid)
    decoded_shifted = decimal_string_to_binary(raw_digits, 23)
    decoded_cipher = unshift_block(decoded_shifted)
    decrypted_cipher = encryption_context_process(22, decoded_cipher, decrypt=True)
    return read_back_parameters(decrypted_cipher)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MSFT 2009 IID decoder/encoder')
    subparsers = parser.add_subparsers(title='Commands', dest='mode')

    enc_p = subparsers.add_parser('encode')
    enc_p.add_argument('group',    type=lambda x: int(x, 0), help='Group ID')
    enc_p.add_argument('serial',   type=lambda x: int(x, 0), help='Serial number')
    enc_p.add_argument('security', type=lambda x: int(x, 0), help='Security ID')
    enc_p.add_argument('hwid',     type=lambda x: int(x, 0), help='Hardware ID')

    dec_p = subparsers.add_parser('decode')
    dec_p.add_argument('iid', type=str, help='Formatted Installation ID')

    rec_p = subparsers.add_parser('recover')
    rec_p.add_argument('iid', type=str, help='Target Formatted Installation ID')
    rec_p.add_argument('last5', type=str, help='Target last 5 characters of the CD-Key (e.g., T83GX)')

    args = parser.parse_args()

    if args.mode == 'decode':
        security, group, serial, hwid = decode_iid(args.iid)
        print(f'Group    : {group}')
        print(f'Serial   : {serial}')
        print(f'Security : {format_security_id_with_gap(security)}')
        print(f'HWID     : {hwid}')

    elif args.mode == 'encode':
        iid = encode_iid(args.group, args.serial, args.security, args.hwid)
        print(iid)

    elif args.mode == 'recover':
        sec_recovered, group, serial, hwid = decode_iid(args.iid)
        base_sec = sec_recovered & (~(0xFFF << 28))
        
        for i in range(4096):
            candidate_sec = base_sec | (i << 28)
            try:
                bk = BinaryKey(group, serial, candidate_sec, True, True)
                if bk.CdKey.endswith(args.last5.upper()):
                    if encode_iid(group, serial, candidate_sec, hwid) == args.iid:
                        print(f"{bk.CdKey} | {candidate_sec} (0x{candidate_sec:016X})")
            except Exception:
                pass

    else:
        parser.print_help()