#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import math
import os
import random
import struct
import sys
import tempfile
import traceback
from struct import pack as pk
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
import zstandard


class Config:
    """Configuration constants"""

    BUFFER_SIZE = 65536
    NCA_HEADER_SIZE = 0x400
    XCI_HEADER_OFFSET = 0xF000
    HFS0_ENTRY_SIZE = 0x40
    PFS0_ENTRY_SIZE = 0x18


class CryptoHandler:
    """Handles AES-CTR encryption/decryption"""

    def __init__(self, key, nonce, offset=0):
        self.key = key
        self.nonce = nonce
        self.seek(offset)

    def encrypt(self, data):
        return self.aes.encrypt(data)

    def decrypt(self, data):
        return self.encrypt(data)

    def seek(self, offset):
        self.ctr = Counter.new(64, prefix=self.nonce[0:8], initial_value=(offset >> 4))
        self.aes = AES.new(self.key, AES.MODE_CTR, counter=self.ctr)


class NCZSection:
    """Represents an NCZ section"""

    def __init__(self, file_handle):
        self.offset = self._read_int64(file_handle)
        self.size = self._read_int64(file_handle)
        self.crypto_type = self._read_int64(file_handle)
        self._read_int64(file_handle)  # padding
        self.crypto_key = file_handle.read(16)
        self.crypto_counter = file_handle.read(16)

    @staticmethod
    def _read_int64(file_handle, byteorder="little"):
        return int.from_bytes(file_handle.read(8), byteorder=byteorder)


class FileParser:
    """Handles parsing of Nintendo Switch file formats"""

    @staticmethod
    def parse_pfs0_offsets(filepath, kb_size=8):
        """Parse PFS0 (NSP) file offsets"""
        files_list = []
        try:
            with open(filepath, "rb") as f:
                data = f.read(int(kb_size * 1024))

            if len(data) < 16 or data[0:4] != b"PFS0":
                return files_list

            n_files = int.from_bytes(data[4:8], byteorder="little")
            st_size = int.from_bytes(data[8:12], byteorder="little")

            string_table_offset = 0x10 + n_files * Config.PFS0_ENTRY_SIZE
            string_table = data[string_table_offset : string_table_offset + st_size]
            header_size = string_table_offset + st_size
            string_end_offset = st_size

            for i in range(n_files):
                idx = n_files - i - 1
                pos = 0x10 + idx * Config.PFS0_ENTRY_SIZE

                if pos + Config.PFS0_ENTRY_SIZE > len(data):
                    break

                offset = int.from_bytes(data[pos : pos + 8], byteorder="little")
                size = int.from_bytes(data[pos + 8 : pos + 16], byteorder="little")
                name_offset = int.from_bytes(
                    data[pos + 16 : pos + 20], byteorder="little"
                )

                if name_offset < string_end_offset:
                    name = (
                        string_table[name_offset:string_end_offset]
                        .decode("utf-8")
                        .rstrip(" \t\r\n\0")
                    )
                    string_end_offset = name_offset

                    file_start = header_size + offset
                    file_end = file_start + size
                    files_list.append([name, file_start, file_end, size])

            files_list.reverse()
        except Exception as e:
            try:
                print(f"Exception parsing NSP: {e}")
            except UnicodeEncodeError:
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Exception parsing NSP: {safe_error}")

        return files_list

    @staticmethod
    def parse_xci_offsets(filepath, kb_size=8):
        """Parse XCI file offsets"""
        try:
            with open(filepath, "rb") as f:
                f.seek(0x100)
                magic = f.read(4)
                if magic != b"HEAD":
                    return []

                secure_offset = int.from_bytes(f.read(4), byteorder="little") * 0x200
                return FileParser._parse_hfs0_offsets(filepath, kb_size, secure_offset)
        except Exception as e:
            print(f"Exception reading XCI: {e}")
            return []

    @staticmethod
    def _parse_hfs0_offsets(filepath, kb_size, base_offset):
        """Parse HFS0 partition offsets"""
        files_list = []
        try:
            with open(filepath, "rb") as f:
                f.seek(base_offset)
                data = f.read(int(kb_size * 1024))

            if len(data) < 16 or data[0:4] != b"HFS0":
                return files_list

            n_files = int.from_bytes(data[4:8], byteorder="little")
            st_size = int.from_bytes(data[8:12], byteorder="little")

            string_table_offset = 0x10 + n_files * Config.HFS0_ENTRY_SIZE
            string_table = data[string_table_offset : string_table_offset + st_size]
            header_size = string_table_offset + st_size
            string_end_offset = st_size

            for i in range(n_files):
                idx = n_files - i - 1
                pos = 0x10 + idx * Config.HFS0_ENTRY_SIZE

                if pos + Config.HFS0_ENTRY_SIZE > len(data):
                    break

                offset = int.from_bytes(data[pos : pos + 8], byteorder="little")
                size = int.from_bytes(data[pos + 8 : pos + 16], byteorder="little")
                name_offset = int.from_bytes(
                    data[pos + 16 : pos + 20], byteorder="little"
                )

                if name_offset < string_end_offset:
                    name = (
                        string_table[name_offset:string_end_offset]
                        .decode("utf-8")
                        .rstrip(" \t\r\n\0")
                    )
                    string_end_offset = name_offset

                    file_start = base_offset + header_size + offset
                    file_end = file_start + size
                    files_list.append([name, file_start, file_end, size])

            files_list.reverse()
        except Exception as e:
            try:
                print(f"Exception parsing HFS0: {e}")
            except UnicodeEncodeError:
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Exception parsing HFS0: {safe_error}")

        return files_list


class HeaderGenerator:
    """Generates headers for Nintendo Switch file formats"""

    @staticmethod
    def generate_pfs0_header(files, file_sizes, alignment=0x10):
        """Generate PFS0 header"""
        files_nb = len(files)
        string_table = "\x00".join(str(nca) for nca in files)
        header_size = 0x10 + files_nb * Config.PFS0_ENTRY_SIZE + len(string_table)
        remainder = (
            alignment - (header_size % alignment) if header_size % alignment != 0 else 0
        )
        header_size += remainder

        file_offsets = [sum(file_sizes[:n]) for n in range(files_nb)]
        file_names_lengths = [len(str(nca)) + 1 for nca in files]
        string_table_offsets = [sum(file_names_lengths[:n]) for n in range(files_nb)]

        header = b"PFS0"
        header += pk("<I", files_nb)
        header += pk("<I", len(string_table) + remainder)
        header += b"\x00\x00\x00\x00"

        for n in range(files_nb):
            header += pk("<Q", file_offsets[n])
            header += pk("<Q", file_sizes[n])
            header += pk("<I", string_table_offsets[n])
            header += b"\x00\x00\x00\x00"

        try:
            header += string_table.encode('utf-8')
        except UnicodeEncodeError:
            # Handle encoding errors by replacing problematic characters
            header += string_table.encode('utf-8', errors='replace')
        header += remainder * b"\x00"
        return header

    @staticmethod
    def generate_hfs0_header(
        file_list, file_sizes=None, sha_list=None, hash_regions=None
    ):
        """Generate HFS0 header"""
        files_nb = len(file_list)
        string_table = "\x00".join(str(nca) for nca in file_list)
        header_size = 0x10 + files_nb * Config.HFS0_ENTRY_SIZE + len(string_table)
        multiplier = math.ceil(header_size / 0x200)
        remainder = 0x200 * multiplier - header_size
        header_size += remainder

        if file_sizes is None:
            file_sizes = [0] * files_nb

        file_offsets = [sum(file_sizes[:n]) for n in range(files_nb)]

        if sha_list is None:
            sha_list = ["00" * 32] * files_nb

        file_names_lengths = [
            len(os.path.basename(str(file))) + 1 for file in file_list
        ]
        string_table_offsets = [sum(file_names_lengths[:n]) for n in range(files_nb)]

        default_hash_region = (0x200).to_bytes(4, byteorder="little")

        header = b"HFS0"
        header += pk("<I", files_nb)
        header += pk("<I", len(string_table) + remainder)
        header += b"\x00\x00\x00\x00"

        for n in range(files_nb):
            header += pk("<Q", file_offsets[n])
            header += pk("<Q", file_sizes[n])
            header += pk("<I", string_table_offsets[n])

            if hash_regions and n < len(hash_regions):
                header += hash_regions[n]
            else:
                header += default_hash_region

            header += b"\x00\x00\x00\x00\x00\x00\x00\x00"
            header += bytes.fromhex(sha_list[n])

        try:
            header += string_table.encode('utf-8')
        except UnicodeEncodeError:
            # Handle encoding errors by replacing problematic characters
            header += string_table.encode('utf-8', errors='replace')
        header += remainder * b"\x00"

        total_size = len(header) + sum(file_sizes)
        return header, total_size, multiplier


class NSPHandler:
    """Handles NSP file operations"""

    def __init__(self, filepath):
        self.filepath = filepath
        self.files = []
        self._parse_header()

    def _parse_header(self):
        """Parse NSP header"""
        with open(self.filepath, "rb") as f:
            magic = f.read(4)
            if magic != b"PFS0":
                raise ValueError("Invalid NSP file")

            file_count = struct.unpack("<I", f.read(4))[0]
            string_table_size = struct.unpack("<I", f.read(4))[0]
            f.read(4)  # Reserved

            for i in range(file_count):
                offset = struct.unpack("<Q", f.read(8))[0]
                size = struct.unpack("<Q", f.read(8))[0]
                name_offset = struct.unpack("<I", f.read(4))[0]
                f.read(4)  # Reserved

                current_pos = f.tell()

                f.seek(0x10 + file_count * 0x18 + name_offset)
                name = b""
                while True:
                    char = f.read(1)
                    if char == b"\x00" or not char:
                        break
                    name += char

                try:
                    decoded_name = name.decode("utf-8")
                except UnicodeDecodeError:
                    decoded_name = name.decode("utf-8", errors="replace")

                self.files.append(
                    {
                        "name": decoded_name,
                        "offset": 0x10 + file_count * 0x18 + string_table_size + offset,
                        "size": size,
                    }
                )

                f.seek(current_pos)

    def get_cnmt_content_sizes(self):
        """Extract content sizes from CNMT metadata"""
        content_sizes = {}

        cnmt_file = next(
            (f for f in self.files if f["name"].endswith(".cnmt.nca")), None
        )
        if not cnmt_file:
            return content_sizes

        try:
            with open(self.filepath, "rb") as f:
                f.seek(cnmt_file["offset"])
                nca_data = f.read(cnmt_file["size"])

                # Check for unencrypted NCA
                if nca_data[0:4] in [b"NCA3", b"NCA2"]:
                    return self._parse_nca_cnmt(nca_data, 0)
                elif nca_data[0x200:0x204] in [b"NCA3", b"NCA2"]:
                    return content_sizes  # Encrypted, skip
                else:
                    return self._parse_raw_cnmt_data(nca_data)
        except Exception:
            return content_sizes

    def _parse_nca_cnmt(self, nca_data, nca_header_offset):
        """Parse CNMT from NCA data"""
        content_sizes = {}

        try:
            section_table_offset = nca_header_offset + 0x240
            if len(nca_data) < section_table_offset + 0x20:
                return content_sizes

            section_offset = struct.unpack(
                "<Q", nca_data[section_table_offset : section_table_offset + 8]
            )[0]

            if section_offset == 0:
                return content_sizes

            pfs0_offset = nca_header_offset + 0x400 + section_offset

            if (
                len(nca_data) < pfs0_offset + 16
                or nca_data[pfs0_offset : pfs0_offset + 4] != b"PFS0"
            ):
                return content_sizes

            file_count = struct.unpack(
                "<I", nca_data[pfs0_offset + 4 : pfs0_offset + 8]
            )[0]
            string_table_size = struct.unpack(
                "<I", nca_data[pfs0_offset + 8 : pfs0_offset + 12]
            )[0]

            for i in range(file_count):
                entry_offset = pfs0_offset + 0x10 + i * 0x18
                if len(nca_data) < entry_offset + 0x18:
                    break

                file_offset = struct.unpack(
                    "<Q", nca_data[entry_offset : entry_offset + 8]
                )[0]
                file_size = struct.unpack(
                    "<Q", nca_data[entry_offset + 8 : entry_offset + 16]
                )[0]
                name_offset = struct.unpack(
                    "<I", nca_data[entry_offset + 16 : entry_offset + 20]
                )[0]

                name_start = pfs0_offset + 0x10 + file_count * 0x18 + name_offset
                if len(nca_data) <= name_start:
                    continue

                filename = b""
                for j in range(name_start, len(nca_data)):
                    if nca_data[j] == 0:
                        break
                    filename += bytes([nca_data[j]])

                filename_str = filename.decode("utf-8", errors="ignore")

                if filename_str.endswith(".cnmt"):
                    cnmt_entry_offset = (
                        pfs0_offset
                        + 0x10
                        + file_count * 0x18
                        + string_table_size
                        + file_offset
                    )
                    if len(nca_data) >= cnmt_entry_offset + file_size:
                        cnmt_data = nca_data[
                            cnmt_entry_offset : cnmt_entry_offset + file_size
                        ]
                        return self._parse_cnmt_data(cnmt_data)
        except Exception:
            pass

        return content_sizes

    def _parse_raw_cnmt_data(self, data):
        """Parse data directly as CNMT"""
        content_sizes = {}

        try:
            for offset in range(0, min(len(data), 0x1000), 0x10):
                if len(data) < offset + 0x20:
                    continue

                title_id = struct.unpack("<Q", data[offset : offset + 8])[0]
                if title_id == 0:
                    continue

                content_count = struct.unpack(
                    "<H", data[offset + 0x0E : offset + 0x10]
                )[0]
                if content_count == 0 or content_count > 100:
                    continue

                extended_header_size = (
                    struct.unpack("<H", data[offset + 0x14 : offset + 0x16])[0]
                    if len(data) >= offset + 0x16
                    else 0
                )
                content_entries_offset = offset + 0x20 + extended_header_size

                parsed_entries = 0
                for i in range(content_count):
                    entry_offset = content_entries_offset + i * 0x38
                    if entry_offset + 0x38 > len(data):
                        break

                    nca_id = data[entry_offset + 0x20 : entry_offset + 0x30].hex()
                    content_size = (
                        struct.unpack(
                            "<Q", data[entry_offset + 0x30 : entry_offset + 0x38]
                        )[0]
                        & 0xFFFFFFFFFFFF
                    )
                    content_type = data[entry_offset + 0x36]

                    if content_size > 0 and len(nca_id) == 32:
                        filename = f"{nca_id}.{'cnmt.' if content_type == 0 else ''}nca"
                        content_sizes[filename] = content_size
                        parsed_entries += 1

                if parsed_entries > 0:
                    return content_sizes
        except Exception:
            pass

        return content_sizes

    def _parse_cnmt_data(self, cnmt_data):
        """Parse CNMT data structure"""
        content_sizes = {}

        if len(cnmt_data) < 0x20:
            return content_sizes

        try:
            content_count = struct.unpack("<H", cnmt_data[0x0E:0x10])[0]

            if content_count == 0 or content_count > 100:
                return content_sizes

            extended_header_size = (
                struct.unpack("<H", cnmt_data[0x14:0x16])[0]
                if len(cnmt_data) >= 0x16
                else 0
            )
            content_entries_offset = 0x20 + extended_header_size

            for i in range(content_count):
                entry_offset = content_entries_offset + i * 0x38
                if entry_offset + 0x38 > len(cnmt_data):
                    break

                nca_id = cnmt_data[entry_offset + 0x20 : entry_offset + 0x30].hex()
                size_bytes = cnmt_data[entry_offset + 0x30 : entry_offset + 0x36]
                content_type = cnmt_data[entry_offset + 0x36]

                content_size = struct.unpack("<Q", size_bytes + b"\x00\x00")[0]

                filename = f"{nca_id}.{'cnmt.' if content_type == 0 else ''}nca"
                content_sizes[filename] = content_size

            return content_sizes
        except Exception:
            return content_sizes

    def read_file(self, filename):
        """Read a specific file from the NSP archive"""
        try:
            for file_entry in self.files:
                if file_entry["name"] == filename:
                    with open(self.filepath, "rb") as f:
                        f.seek(file_entry["offset"])
                        return f.read(file_entry["size"])
            return None
        except Exception:
            return None


class XCIHandler:
    """Handles XCI file operations"""

    def __init__(self, filepath):
        self.filepath = filepath
        self.files = []
        self._parse_header()

    def _parse_header(self):
        """Parse XCI header"""
        with open(self.filepath, "rb") as f:
            magic = f.read(4)
            if magic != b"HEAD":
                raise ValueError("Invalid XCI file")

            f.seek(Config.XCI_HEADER_OFFSET)
            magic = f.read(4)
            if magic != b"HFS0":
                return

            file_count = struct.unpack("<I", f.read(4))[0]
            string_table_size = struct.unpack("<I", f.read(4))[0]
            f.read(4)  # Reserved

            for i in range(file_count):
                offset = struct.unpack("<Q", f.read(8))[0]
                size = struct.unpack("<Q", f.read(8))[0]
                name_offset = struct.unpack("<I", f.read(4))[0]
                f.read(4)  # Reserved

                current_pos = f.tell()

                f.seek(
                    Config.XCI_HEADER_OFFSET + 0x10 + file_count * 0x20 + name_offset
                )
                name = b""
                while True:
                    char = f.read(1)
                    if char == b"\x00" or not char:
                        break
                    name += char

                self.files.append(
                    {
                        "name": name.decode("utf-8"),
                        "offset": Config.XCI_HEADER_OFFSET
                        + 0x10
                        + file_count * 0x20
                        + string_table_size
                        + offset,
                        "size": size,
                    }
                )

                f.seek(current_pos)


class CompressionHandler:
    """Handles NSZ/XCZ/NCZ compression and decompression"""

    @staticmethod
    def decompress_ncz(input_path, output_path):
        """Decompress NCZ to NCA"""
        try:
            with open(input_path, "rb") as f:
                header = f.read(0x4000)
                magic = NCZSection._read_int64(f)
                section_count = NCZSection._read_int64(f)
                sections = [NCZSection(f) for _ in range(section_count)]

                dctx = zstandard.ZstdDecompressor()
                reader = dctx.stream_reader(f)

                with open(output_path, "wb+") as o:
                    o.write(header)

                    while True:
                        chunk = reader.read(16384)
                        if not chunk:
                            break
                        o.write(chunk)

                    for section in sections:
                        if section.crypto_type == 1:
                            continue

                        if section.crypto_type != 3:
                            raise IOError(f"Unknown crypto type: {section.crypto_type}")

                        crypto = CryptoHandler(
                            section.crypto_key, section.crypto_counter
                        )
                        CompressionHandler._decrypt_section(
                            o, crypto, section.offset, section.size
                        )
            return True
        except Exception as e:
            print(f"Error decompressing NCZ {input_path}: {e}")
            return False

    @staticmethod
    def _decrypt_section(file_handle, crypto, offset, size):
        """Decrypt a section of the file"""
        current_pos = offset
        end_pos = offset + size

        while current_pos < end_pos:
            file_handle.seek(current_pos)
            crypto.seek(current_pos)
            chunk_size = min(0x10000, end_pos - current_pos)
            buf = file_handle.read(chunk_size)

            if not buf:
                break

            file_handle.seek(current_pos)
            file_handle.write(crypto.encrypt(buf))
            current_pos += chunk_size

    @staticmethod
    def decompress_nsz(input_path, output_path, buffer_size=Config.BUFFER_SIZE):
        """Decompress NSZ to NSP"""
        try:
            print(f"Decompressing NSZ: {input_path} -> {output_path}")

            files_list = FileParser.parse_pfs0_offsets(input_path)
            if not files_list:
                print("Failed to parse NSP structure")
                return False

            nca_files = []
            file_sizes = []
            temp_files = []

            with open(input_path, "rb") as f:
                for file_info in files_list:
                    name, start_offset, end_offset, size = file_info

                    if name.endswith(".ncz"):
                        temp_ncz = tempfile.NamedTemporaryFile(
                            delete=False, suffix=".ncz"
                        )
                        temp_ncz.close()
                        temp_files.append(temp_ncz.name)

                        f.seek(start_offset)
                        ncz_data = f.read(size)

                        with open(temp_ncz.name, "wb") as temp_f:
                            temp_f.write(ncz_data)

                        temp_nca = tempfile.NamedTemporaryFile(
                            delete=False, suffix=".nca"
                        )
                        temp_nca.close()
                        temp_files.append(temp_nca.name)

                        if CompressionHandler.decompress_ncz(
                            temp_ncz.name, temp_nca.name
                        ):
                            decompressed_size = os.path.getsize(temp_nca.name)
                            nca_files.append(
                                (
                                    name.replace(".ncz", ".nca"),
                                    temp_nca.name,
                                    decompressed_size,
                                    True,
                                )
                            )
                            file_sizes.append(decompressed_size)
                        else:
                            try:
                                print(f"Failed to decompress {name}")
                            except UnicodeEncodeError:
                                safe_name = name.encode('ascii', errors='replace').decode('ascii')
                                print(f"Failed to decompress {safe_name}")
                            FileUtils.cleanup_temp_files(temp_files)
                            return False
                    else:
                        nca_files.append((name, None, size, False))
                        file_sizes.append(size)

            file_names = [info[0] for info in nca_files]
            header = HeaderGenerator.generate_pfs0_header(file_names, file_sizes)

            with open(output_path, "wb") as out_f:
                out_f.write(header)

                with open(input_path, "rb") as in_f:
                    for i, (name, temp_path, size, is_decompressed) in enumerate(
                        nca_files
                    ):
                        if is_decompressed and temp_path:
                            with open(temp_path, "rb") as temp_f:
                                while True:
                                    chunk = temp_f.read(buffer_size)
                                    if not chunk:
                                        break
                                    out_f.write(chunk)
                        else:
                            file_info = files_list[i]
                            start_offset = file_info[1]
                            FileUtils.copy_file_content(
                                input_path, out_f, start_offset, size, buffer_size
                            )

            FileUtils.cleanup_temp_files(temp_files)
            try:
                print(f"NSZ decompression completed: {output_path}")
            except UnicodeEncodeError:
                safe_path = output_path.encode('ascii', errors='replace').decode('ascii')
                print(f"NSZ decompression completed: {safe_path}")
            return True
        except Exception as e:
            try:
                print(f"Error decompressing NSZ {input_path}: {e}")
            except UnicodeEncodeError:
                safe_path = input_path.encode('ascii', errors='replace').decode('ascii')
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Error decompressing NSZ {safe_path}: {safe_error}")
            return False


class XCIGenerator:
    """Generates XCI files from various inputs"""

    @staticmethod
    def generate_random_hex(size):
        """Generate random hex string"""
        return "".join(random.choice("0123456789ABCDEF") for _ in range(size * 2))

    @staticmethod
    def get_gamecard_size(bytes_size):
        """Get game card size based on file size"""
        gb_size = bytes_size / (1024 * 1024 * 1024)

        size_mappings = [
            (32, 0xE3, "1000a100"),
            (16, 0xE2, "1000a100"),
            (8, 0xE1, "1000a100"),
            (4, 0xE0, "1000a100"),
            (2, 0xF0, "1100a100"),
            (1, 0xF8, "1100a100"),
            (0, 0xFA, "1100a100"),
        ]

        for threshold, card, firm_ver in size_mappings:
            if gb_size >= threshold:
                return card, firm_ver

        return 0xFA, "1100a100"

    @staticmethod
    def get_encrypted_gameinfo(bytes_size):
        """Generate encrypted game info"""
        gb_size = bytes_size / (1024 * 1024 * 1024)

        if gb_size >= 4:
            params = {
                "firm_ver": 0x9298F35088F09F7D,
                "access_freq": 0xA89A60D4,
                "read_wait_time": 0xCBA6F96F,
                "read_wait_time2": 0xA45BB6AC,
                "write_wait_time": 0xABC751F9,
                "write_wait_time2": 0x5D398742,
                "firmware_mode": 0x6B38C3F2,
                "cup_version": 0x10DA0B70,
                "empty1": 0x0E5ECE29,
                "upd_hash": 0xA13CBE1DA6D052CB,
                "cup_id": 0xF2087CE9AF590538,
                "empty2": 0x570D78B9CDD27FBEB4A0AC2ADFF9BA77754DD6675AC76223506B3BDABCB2E212FA465111AB7D51AFC8B5B2B21C4B3F40654598620282ADD6,
            }
        else:
            params = {
                "firm_ver": 0x9109FF82971EE993,
                "access_freq": 0x5011CA06,
                "read_wait_time": 0x3F3C4D87,
                "read_wait_time2": 0xA13D28A9,
                "write_wait_time": 0x928D74F1,
                "write_wait_time2": 0x49919EB7,
                "firmware_mode": 0x82E1F0CF,
                "cup_version": 0xE4A5A3BD,
                "empty1": 0xF978295C,
                "upd_hash": 0xD52639A4991BDB1F,
                "cup_id": 0xED841779A3F85D23,
                "empty2": 0xAA4242135616F5187C03CF0D97E5D218FDB245381FD1CF8DFB796FBEDA4BF7F7D6B128CE89BC9EAA8552D42F597C5DB866C67BB0DD8EEA11,
            }

        game_info = b""
        for key in [
            "firm_ver",
            "access_freq",
            "read_wait_time",
            "read_wait_time2",
            "write_wait_time",
            "write_wait_time2",
            "firmware_mode",
            "cup_version",
            "empty1",
            "upd_hash",
            "cup_id",
        ]:
            size = 8 if key in ["firm_ver", "upd_hash", "cup_id"] else 4
            game_info += params[key].to_bytes(size, byteorder="big")

        game_info += params["empty2"].to_bytes(56, byteorder="big")
        return game_info

    @staticmethod
    def generate_xci_header(file_list, file_sizes, hash_list):
        """Generate complete XCI header structure"""
        # Generate partition headers
        upd_header, upd_size, upd_multiplier = HeaderGenerator.generate_hfs0_header(
            [], [], []
        )
        norm_header, norm_size, norm_multiplier = HeaderGenerator.generate_hfs0_header(
            [], [], []
        )
        sec_header, sec_size, sec_multiplier = HeaderGenerator.generate_hfs0_header(
            file_list, file_sizes, hash_list
        )

        # Generate root header
        root_hreg = [
            (0x200 * upd_multiplier).to_bytes(4, byteorder="little"),
            (0x200 * norm_multiplier).to_bytes(4, byteorder="little"),
            (0x200 * sec_multiplier).to_bytes(4, byteorder="little"),
        ]

        root_list = ["update", "normal", "secure"]
        root_file_sizes = [upd_size, norm_size, sec_size]
        root_hash_list = [
            SHA256.new(upd_header).hexdigest(),
            SHA256.new(norm_header).hexdigest(),
            SHA256.new(sec_header).hexdigest(),
        ]

        root_header, root_size, root_multiplier = HeaderGenerator.generate_hfs0_header(
            root_list, root_file_sizes, root_hash_list, root_hreg
        )

        tot_size = Config.XCI_HEADER_OFFSET + root_size

        # Generate XCI header components
        signature = bytes.fromhex(XCIGenerator.generate_random_hex(0x100))

        sec_offset = root_header[0x90:0x98]
        sec_offset = int.from_bytes(sec_offset, byteorder="little")
        sec_offset = int((sec_offset + Config.XCI_HEADER_OFFSET + 0x200) / 0x200)
        sec_offset = sec_offset.to_bytes(4, byteorder="little")

        back_offset = (0xFFFFFFFF).to_bytes(4, byteorder="little")
        kek = (0x00).to_bytes(1, byteorder="big")
        cardsize, access_freq = XCIGenerator.get_gamecard_size(tot_size)
        cardsize = cardsize.to_bytes(1, byteorder="big")
        gc_ver = (0x00).to_bytes(1, byteorder="big")
        gc_flag = (0x00).to_bytes(1, byteorder="big")
        pack_id = (0x8750F4C0A9C5A966).to_bytes(8, byteorder="big")
        valid_data = int(((tot_size - 0x1) / 0x200))
        valid_data = valid_data.to_bytes(8, byteorder="little")

        iv = (0x5B408B145E277E81E5BF677C94888D7B).to_bytes(16, byteorder="big")
        hfs0_offset = (Config.XCI_HEADER_OFFSET).to_bytes(8, byteorder="little")
        len_rhfs0 = (len(root_header)).to_bytes(8, byteorder="little")
        sha_rheader = SHA256.new(root_header[0x00:0x200]).digest()
        sha_ini_data = bytes.fromhex(
            "1AB7C7B263E74E44CD3C68E40F7EF4A4D6571551D043FCA8ECF5C489F2C66E7E"
        )
        sm_flag = (0x01).to_bytes(4, byteorder="little")
        tk_flag = (0x02).to_bytes(4, byteorder="little")
        k_flag = (0x0).to_bytes(4, byteorder="little")
        end_norm = sec_offset

        header = b""
        header += signature
        header += b"HEAD"
        header += sec_offset
        header += back_offset
        header += kek
        header += cardsize
        header += gc_ver
        header += gc_flag
        header += pack_id
        header += valid_data
        header += iv
        header += hfs0_offset
        header += len_rhfs0
        header += sha_rheader
        header += sha_ini_data
        header += sm_flag
        header += tk_flag
        header += k_flag
        header += end_norm

        enc_info = XCIGenerator.get_encrypted_gameinfo(tot_size)
        sig_padding = bytes(0x6E00)
        fake_cert = bytes(0x8000)

        return (
            header,
            enc_info,
            sig_padding,
            fake_cert,
            root_header,
            upd_header,
            norm_header,
            sec_header,
            root_size,
            upd_multiplier,
            norm_multiplier,
            sec_multiplier,
        )


class FileUtils:
    """File utility functions"""

    @staticmethod
    def copy_file_content(
        src_path, dst_file, offset, size, buffer_size=Config.BUFFER_SIZE
    ):
        """Copy file content from source to destination"""
        with open(src_path, "rb") as src:
            src.seek(offset)
            remaining = size

            while remaining > 0:
                chunk_size = min(buffer_size, remaining)
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                dst_file.write(chunk)
                remaining -= len(chunk)

    @staticmethod
    def cleanup_temp_files(temp_files):
        """Clean up temporary files and directories"""
        if not temp_files:
            return

        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                temp_dir = os.path.dirname(temp_file)
                if os.path.exists(temp_dir) and not os.listdir(temp_dir):
                    os.rmdir(temp_dir)
            except Exception:
                pass

    @staticmethod
    def set_nca_gamecard_flag(nca_path):
        """Set gamecard flag in NCA header for XCI compatibility"""
        try:
            with open(nca_path, "r+b") as f:
                f.seek(0x204)
                current_flag = f.read(1)

                if current_flag == b"\x00":
                    f.seek(0x204)
                    f.write(b"\x01")
                    f.flush()
        except Exception:
            pass

    @staticmethod
    def decompress_file(filepath, buffer_size=Config.BUFFER_SIZE):
        """Decompress a single file and return the decompressed path"""
        if not filepath.endswith((".nsz", ".xcz", ".ncz")):
            return filepath

        temp_dir = tempfile.mkdtemp()
        basename = os.path.basename(filepath)

        if filepath.endswith(".nsz"):
            temp_file = os.path.join(temp_dir, basename[:-1] + "p")
            CompressionHandler.decompress_nsz(filepath, temp_file, buffer_size)
        elif filepath.endswith(".ncz"):
            temp_file = os.path.join(temp_dir, basename[:-1] + "a")
            if CompressionHandler.decompress_ncz(filepath, temp_file):
                return temp_file
            else:
                return filepath

        return temp_file


class SquirrelMinimal:
    """Main application class"""

    def __init__(self):
        self.parser = self._create_argument_parser()

    def _create_argument_parser(self):
        """Create and configure argument parser"""
        parser = argparse.ArgumentParser(
            description="Squirrel Minimal - NSP/XCI repackaging and NSZ/XCZ decompression"
        )

        parser.add_argument("file", nargs="*", help="Input files")
        parser.add_argument(
            "-dc", "--direct_creation", nargs="+", help="Create directly a nsp or xci"
        )
        parser.add_argument(
            "-dmul",
            "--direct_multi",
            nargs="+",
            help="Create directly a multi nsp or xci",
        )
        parser.add_argument(
            "-dcpr", "--decompress", help="Decompress a nsz, xcz or ncz"
        )

        parser.add_argument("-o", "--ofolder", nargs="+", help="Set output folder")
        parser.add_argument(
            "-tfile", "--text_file", help="Input text file with file list"
        )
        parser.add_argument(
            "-b",
            "--buffer",
            type=int,
            default=Config.BUFFER_SIZE,
            help="Set buffer size",
        )
        parser.add_argument(
            "-t", "--type", default="xci", help="Set output type (xci only)"
        )
        parser.add_argument("-rn", "--rename", help="Rename output file")

        return parser

    def run(self, args=None):
        """Main entry point"""
        args = self.parser.parse_args(args)

        try:
            if args.decompress:
                return self._handle_decompression(args)
            elif args.direct_multi:
                return self._handle_direct_multi(args)
            else:
                self.parser.print_help()
                return 0
        except Exception as e:
            try:
                print(f"Error: {e}")
            except UnicodeEncodeError:
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Error: {safe_error}")
            traceback.print_exc()
            return 1

    def _get_output_folder(self, args):
        """Get output folder from args or create default"""
        if args.ofolder:
            ofolder = (
                args.ofolder[0] if isinstance(args.ofolder, list) else args.ofolder
            )
        else:
            ofolder = os.path.join(os.getcwd(), "output")

        os.makedirs(ofolder, exist_ok=True)
        return ofolder

    def _get_input_file(self, text_file, direct_file):
        """Get input file from text file or direct argument"""
        if text_file:
            with open(text_file, "r", encoding="utf8") as f:
                return os.path.abspath(f.readline().strip())
        return direct_file

    def _get_file_list(self, text_file):
        """Get list of existing files from text file"""
        file_list = []
        try:
            with open(text_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and os.path.exists(line):
                        file_list.append(line)
        except Exception as e:
            try:
                print(f"Error reading manifest file: {e}")
            except UnicodeEncodeError:
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Error reading manifest file: {safe_error}")
        return file_list

    def _handle_decompression(self, args):
        """Handle NSZ/XCZ/NCZ decompression"""
        ofolder = self._get_output_folder(args)
        filepath = self._get_input_file(args.text_file, args.decompress)
        basename = os.path.basename(filepath)

        if filepath.endswith(".nsz"):
            outfile = os.path.join(ofolder, basename[:-1] + "p")
            success = CompressionHandler.decompress_nsz(filepath, outfile, args.buffer)
        elif filepath.endswith(".ncz"):
            outfile = os.path.join(ofolder, basename[:-1] + "a")
            success = CompressionHandler.decompress_ncz(filepath, outfile)
        else:
            raise ValueError(f"Unsupported file type: {filepath}")

        return 0 if success else 1

    def _handle_direct_multi(self, args):
        """Handle direct multi creation"""
        if len(args.direct_multi) < 1:
            return 1

        if args.text_file:
            file_list = self._get_file_list(args.text_file)
            if not file_list:
                return 1
        else:
            file_list = [f for f in args.direct_multi if os.path.exists(f)]
            if not file_list:
                print("No valid input files found")
                return 1

        ofolder = self._get_output_folder(args)
        output_file = os.path.join(ofolder, "Multi_Content.xci")

        try:
            success = self._create_multi_xci(file_list, output_file, args)
            return 0 if success else 1
        finally:
            pass

    def _create_multi_xci(self, file_list, outfile, args):
        """Create multi-XCI file"""
        try:
            # Phase 1: Decompression
            processed_files = []
            temp_files = []

            for filepath in file_list:
                processed_file = FileUtils.decompress_file(filepath, args.buffer)
                processed_files.append(processed_file)
                if processed_file != filepath:
                    temp_files.append(processed_file)

            # Phase 2: Generate proper filename from metadata
            filename = self._generate_multi_filename(processed_files)
            if filename:
                # Update output file with proper name
                output_dir = os.path.dirname(outfile)
                outfile = os.path.join(output_dir, filename + ".xci")
                try:
                    print(f"Filename: {filename}.xci")
                except UnicodeEncodeError:
                    # Handle Unicode characters in console output
                    safe_filename = filename.encode('ascii', errors='replace').decode('ascii')
                    print(f"Filename: {safe_filename}.xci")
                    print("Warning: Some Unicode characters were replaced in console output")

            # Phase 3: Content Analysis
            all_files = []
            all_sizes = []

            for filepath in processed_files:
                if filepath.endswith(".nsp"):
                    try:
                        nsp = NSPHandler(filepath)
                        content_sizes = nsp.get_cnmt_content_sizes()
                    except Exception:
                        content_sizes = {}

                    for file_entry in nsp.files:
                        if file_entry["name"].endswith(".nca"):
                            all_files.append(file_entry["name"])
                            if file_entry["name"] in content_sizes:
                                all_sizes.append(content_sizes[file_entry["name"]])
                            else:
                                all_sizes.append(file_entry["size"])
                elif filepath.endswith(".nca"):
                    all_files.append(os.path.basename(filepath))
                    all_sizes.append(os.path.getsize(filepath))

            # Add dummy files if needed
            while len(all_files) <= 3:
                dummy_name = "0" * (4 - len(all_files))
                all_files.append(dummy_name)
                all_sizes.append(0)

            # Generate file hashes
            sec_hashlist = []
            print("Calculating SHA256 hashes for NCA files...")

            for filename in all_files:
                if filename in ["0", "00", "000"]:
                    sha = "0" * 64
                    sec_hashlist.append(sha)
                    continue

                sha = "0" * 64  # Default fallback

                for filepath in processed_files:
                    if filepath.endswith(".nsp"):
                        try:
                            nsp = NSPHandler(filepath)
                            for file_entry in nsp.files:
                                if file_entry["name"] == filename and file_entry[
                                    "name"
                                ].endswith(".nca"):
                                    with open(filepath, "rb") as nsp_file:
                                        nsp_file.seek(file_entry["offset"])
                                        header_block = nsp_file.read(0x200)
                                        if len(header_block) == 0x200:
                                            sha = SHA256.new(header_block).hexdigest()
                                    break
                        except Exception:
                            pass
                    elif (
                        filepath.endswith(".nca")
                        and os.path.basename(filepath) == filename
                    ):
                        try:
                            with open(filepath, "rb") as nca_file:
                                header_block = nca_file.read(0x200)
                                if len(header_block) == 0x200:
                                    sha = SHA256.new(header_block).hexdigest()
                        except Exception:
                            pass

                sec_hashlist.append(sha)
                if sha != "0" * 64:
                    try:
                        print(f"  {filename}: {sha[:16]}...")
                    except UnicodeEncodeError:
                        safe_filename = filename.encode('ascii', errors='replace').decode('ascii')
                        print(f"  {safe_filename}: {sha[:16]}...")

            # Generate XCI header
            header_components = XCIGenerator.generate_xci_header(
                all_files, all_sizes, sec_hashlist
            )

            # Write XCI file
            with open(outfile, "wb") as xci_file:
                try:
                    print(f"Writing XCI header to {outfile}...")
                except UnicodeEncodeError:
                    safe_outfile = outfile.encode('ascii', errors='replace').decode('ascii')
                    print(f"Writing XCI header to {safe_outfile}...")

                # Write header components
                for component in header_components[:8]:
                    xci_file.write(component)

                print("XCI header written successfully, now writing content files...")

                # Create file mapping
                file_mapping = {}
                for filepath in processed_files:
                    if filepath.endswith(".nsp"):
                        nsp = NSPHandler(filepath)
                        for file_entry in nsp.files:
                            if file_entry["name"].endswith(".nca"):
                                file_mapping[file_entry["name"]] = {
                                    "source_file": filepath,
                                    "offset": file_entry["offset"],
                                    "size": file_entry["size"],
                                    "type": "nsp",
                                }
                    elif filepath.endswith(".nca"):
                        filename = os.path.basename(filepath)
                        file_mapping[filename] = {
                            "source_file": filepath,
                            "offset": 0,
                            "size": os.path.getsize(filepath),
                            "type": "nca",
                        }

                # Write file content
                for filename in all_files:
                    if filename in ["0", "00", "000"]:
                        continue

                    if filename not in file_mapping:
                        continue

                    file_info = file_mapping[filename]

                    if file_info["type"] == "nsp":
                        temp_nca = os.path.join(tempfile.gettempdir(), filename)
                        with open(file_info["source_file"], "rb") as nsp_file:
                            nsp_file.seek(file_info["offset"])
                            nca_data = nsp_file.read(file_info["size"])
                            with open(temp_nca, "wb") as nca_file:
                                nca_file.write(nca_data)

                        FileUtils.set_nca_gamecard_flag(temp_nca)

                        with open(temp_nca, "rb") as nca_file:
                            while True:
                                buf = nca_file.read(args.buffer)
                                if not buf:
                                    break
                                xci_file.write(buf)

                        try:
                            os.remove(temp_nca)
                        except Exception:
                            pass

                    elif file_info["type"] == "nca":
                        temp_nca = os.path.join(tempfile.gettempdir(), filename)
                        import shutil

                        shutil.copy2(file_info["source_file"], temp_nca)

                        FileUtils.set_nca_gamecard_flag(temp_nca)

                        with open(temp_nca, "rb") as nca_file:
                            while True:
                                chunk = nca_file.read(args.buffer)
                                if not chunk:
                                    break
                                xci_file.write(chunk)

                        try:
                            os.remove(temp_nca)
                        except Exception:
                            pass

            try:
                print(f"XCI file creation completed successfully: {outfile}")
            except UnicodeEncodeError:
                safe_outfile = outfile.encode('ascii', errors='replace').decode('ascii')
                print(f"XCI file creation completed successfully: {safe_outfile}")

            if temp_files:
                FileUtils.cleanup_temp_files(temp_files)

            return True

        except Exception as e:
            try:
                print(f"Error creating XCI file: {str(e)}")
            except UnicodeEncodeError:
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Error creating XCI file: {safe_error}")
            traceback.print_exc()

            if "temp_files" in locals() and temp_files:
                FileUtils.cleanup_temp_files(temp_files)
            return False

    def _generate_multi_filename(self, file_list):
        """Generate filename based on game metadata like squirrel.py"""
        try:
            # Analyze content to build filename
            basecount = 0
            updcount = 0
            dlccount = 0
            baseid = ""
            updid = ""
            dlcid = ""
            basever = ""
            updver = ""
            dlcver = ""
            basefile = ""
            updfile = ""
            dlcfile = ""
            ctitl = "UNKNOWN"
            
            # Process each file to extract metadata
            for filepath in file_list:
                if filepath.endswith(".nsp"):
                    try:
                        nsp = NSPHandler(filepath)
                        # Find CNMT file to get metadata
                        for file_entry in nsp.files:
                            if file_entry["name"].endswith(".cnmt.nca"):
                                # Extract basic info from filename patterns
                                basename = os.path.basename(filepath)
                                
                                # Try to extract title ID from filename
                                import re
                                tid_match = re.search(r'\[([0-9A-Fa-f]{16})\]', basename)
                                if tid_match:
                                    titleid = tid_match.group(1).upper()
                                    
                                    # Try to extract version
                                    ver_match = re.search(r'\[v(\d+)\]', basename)
                                    version = ver_match.group(1) if ver_match else "0"
                                    
                                    # Determine content type based on title ID
                                    if titleid.endswith("000"):
                                        # Base game
                                        basecount += 1
                                        if baseid == "":
                                            baseid = titleid
                                            basever = f"[v{version}]"
                                            basefile = filepath
                                    elif titleid.endswith("800"):
                                        # Update
                                        updcount += 1
                                        if updid == "":
                                            updid = titleid
                                            updver = f"[v{version}]"
                                            updfile = filepath
                                    else:
                                        # DLC
                                        dlccount += 1
                                        if dlcid == "":
                                            dlcid = titleid
                                            dlcver = f"[v{version}]"
                                            dlcfile = filepath
                                break
                    except Exception:
                        pass
            
            # Generate content count tag
            bctag = f"{basecount}G" if basecount != 0 else ""
            updtag = f"+{updcount}U" if updcount != 0 and bctag != "" else f"{updcount}U" if updcount != 0 else ""
            dctag = f"+{dlccount}D" if dlccount != 0 and (bctag != "" or updtag != "") else f"{dlccount}D" if dlccount != 0 else ""
            ccount = f"({bctag}{updtag}{dctag})" if bctag or updtag or dctag else ""
            
            # Simplify count for single content
            if ccount in ["(1G)", "(1U)", "(1D)"]:
                ccount = ""
            
            # Extract game title from CONTROL NCA instead of filename
            if basefile:
                ctitl = self._extract_title_from_nca(basefile) or self._extract_title_from_filename(basefile)
                target_id = f"[{baseid}]"
                target_ver = updver if updver else basever
            elif updfile:
                ctitl = self._extract_title_from_nca(updfile) or self._extract_title_from_filename(updfile)
                target_id = f"[{updid}]"
                target_ver = updver
            elif dlcfile:
                ctitl = self._extract_title_from_nca(dlcfile) or self._extract_title_from_filename(dlcfile)
                target_id = f"[{dlcid}]"
                target_ver = dlcver
            else:
                return None
            
            # Build final filename
            endname = f"{ctitl} {target_id}{target_ver} {ccount}".strip()
            
            # Clean up filename
            endname = self._clean_filename(endname)
            
            return endname
            
        except Exception as e:
            try:
                print(f"Error generating filename: {e}")
            except UnicodeEncodeError:
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Error generating filename: {safe_error}")
            return None
    
    def _extract_title_from_nca(self, filepath):
        """Extract game title from CONTROL NCA file like squirrel.py"""
        try:
            nsp = NSPHandler(filepath)
            
            # Find CONTROL NCA file
            control_nca_data = None
            for file_entry in nsp.files:
                if file_entry["name"].endswith(".nca"):
                    # Read NCA header to check if it's CONTROL type
                    nca_data = nsp.read_file(file_entry["name"])
                    if len(nca_data) >= 0x220:
                        # Check content type at offset 0x20C (CONTROL = 1)
                        content_type = int.from_bytes(nca_data[0x20C:0x20D], 'little')
                        if content_type == 1:  # CONTROL NCA
                            control_nca_data = nca_data
                            break
            
            if not control_nca_data:
                return None
            
            # Extract title from CONTROL NCA language blocks
            title = self._extract_title_from_control_nca(control_nca_data)
            return title if title and title != "UNKNOWN" else None
            
        except Exception as e:
            try:
                print(f"Error extracting title from NCA: {e}")
            except UnicodeEncodeError:
                safe_error = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"Error extracting title from NCA: {safe_error}")
            return None
    
    def _extract_title_from_control_nca(self, nca_data):
        """Extract title from CONTROL NCA language blocks"""
        try:
            # Language offsets in CONTROL NCA (similar to squirrel.py)
            language_offsets = [
                0x14200,  # US English
                0x14400,  # UK English  
                0x14000,  # Japanese
                0x14600,  # French
                0x14800,  # German
                0x14A00,  # Italian
                0x14C00,  # Spanish
                0x14E00,  # Chinese (Simplified)
                0x15000,  # Korean
                0x15200,  # Dutch
                0x15400,  # Portuguese
                0x15600,  # Russian
                0x15800,  # Chinese (Traditional)
            ]
            
            for offset in language_offsets:
                try:
                    if offset + 0x200 <= len(nca_data):
                        # Read title (first 0x200 bytes of language block)
                        title_bytes = nca_data[offset:offset + 0x200]
                        
                        # Find null terminator
                        null_pos = title_bytes.find(b'\x00')
                        if null_pos > 0:
                            title_bytes = title_bytes[:null_pos]
                        
                        # Decode title
                        title = title_bytes.decode('utf-8', errors='ignore').strip()
                        
                        if title and len(title) > 1 and title != "UNKNOWN":
                            # Clean up the title
                            title = title.replace('\x00', '').strip()
                            if title:
                                return title
                except Exception:
                    continue
            
            return "UNKNOWN"
            
        except Exception:
            return "UNKNOWN"
    
    def _extract_title_from_filename(self, filepath):
        """Extract game title from filename"""
        try:
            basename = os.path.basename(filepath)
            # Remove file extension
            title = os.path.splitext(basename)[0]
            
            # Remove common patterns like [titleid], [version], etc.
            import re
            title = re.sub(r'\[[^\]]*\]', '', title)  # Remove [brackets]
            title = re.sub(r'\([^\)]*\)', '', title)  # Remove (parentheses)
            title = re.sub(r'\s+', ' ', title)  # Normalize spaces
            title = title.strip()
            
            # Remove common suffixes
            suffixes = ['.nsp', '.xci', '.nsz', '.xcz']
            for suffix in suffixes:
                if title.lower().endswith(suffix):
                    title = title[:-len(suffix)]
            
            return title if title else "UNKNOWN"
        except Exception:
            return "UNKNOWN"
    
    def _clean_filename(self, filename):
        """Clean filename like squirrel.py does"""
        import re
        
        # Remove invalid characters
        filename = re.sub(r'[/\\:*?]+', '', filename)
        filename = re.sub(r'[™©®`~^´ªº¢#£€¥$ƒ±¬½¼♡«»±•²‰œæÆ³☆<<>>|]', '', filename)
        
        # Replace Roman numerals
        replacements = {
            'Ⅰ': 'I', 'Ⅱ': 'II', 'Ⅲ': 'III', 'Ⅳ': 'IV', 'Ⅴ': 'V',
            'Ⅵ': 'VI', 'Ⅶ': 'VII', 'Ⅷ': 'VIII', 'Ⅸ': 'IX', 'Ⅹ': 'X',
            'Ⅺ': 'XI', 'Ⅻ': 'XII', 'Ⅼ': 'L', 'Ⅽ': 'C', 'Ⅾ': 'D', 'Ⅿ': 'M',
            '—': '-', '√': 'Root'
        }
        
        for old, new in replacements.items():
            filename = filename.replace(old, new)
        
        # Replace accented characters
        accents = {
            'àâá@äå': 'a', 'ÀÂÁÄÅ': 'A', 'èêéë': 'e', 'ÈÊÉË': 'E',
            'ìîíï': 'i', 'ÌÎÍÏ': 'I', 'òôóöø': 'o', 'ÒÔÓÖØ': 'O',
            'ùûúü': 'u', 'ÙÛÚÜ': 'U'
        }
        
        for chars, replacement in accents.items():
            for char in chars:
                filename = filename.replace(char, replacement)
        
        # Clean up quotes and spaces
        filename = filename.replace("'", "'")
        filename = re.sub(r'\s+', ' ', filename)
        filename = filename.strip()
        
        return filename


def main():
    """Main entry point"""
    app = SquirrelMinimal()
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
