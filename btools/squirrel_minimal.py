#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import tempfile
import struct
import random
import re
import math
import traceback
from binascii import unhexlify as uhx
from pathlib import Path
from hashlib import sha256
from struct import pack as pk

from Crypto.Cipher import AES
from Crypto.Util import Counter
import zstandard

# Constants
BUFFER_SIZE = 65536
NCA_HEADER_SIZE = 0x400
XCI_HEADER_OFFSET = 0xF000
HFS0_ENTRY_SIZE = 0x40
PFS0_ENTRY_SIZE = 0x18

# Utility functions
def read_int64(f, byteorder='little', signed=False):
    """Read 64-bit integer from file"""
    return int.from_bytes(f.read(8), byteorder=byteorder, signed=signed)

def read_int128(f, byteorder='little', signed=False):
    """Read 128-bit integer from file"""
    return int.from_bytes(f.read(16), byteorder=byteorder, signed=signed)

def randhex(size):
    """Generate random hex string"""
    return ''.join(random.choice('0123456789ABCDEF') for _ in range(size * 2))

def cleanup_temp_files(temp_files):
    """Clean up temporary files and directories"""
    if not temp_files:
        return
    for temp_file in temp_files:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            # Remove empty temp directory
            temp_dir = os.path.dirname(temp_file)
            if os.path.exists(temp_dir) and not os.listdir(temp_dir):
                os.rmdir(temp_dir)
        except Exception:
            pass  # Silently handle cleanup errors

class AESCTR:
    """AES-CTR encryption/decryption handler"""
    def __init__(self, key, nonce, offset=0):
        self.key = key
        self.nonce = nonce
        self.seek(offset)

    def encrypt(self, data, ctr=None):
        if ctr is None:
            ctr = self.ctr
        return self.aes.encrypt(data)

    def decrypt(self, data, ctr=None):
        return self.encrypt(data, ctr)

    def seek(self, offset):
        self.ctr = Counter.new(64, prefix=self.nonce[0:8], initial_value=(offset >> 4))
        self.aes = AES.new(self.key, AES.MODE_CTR, counter=self.ctr)

class Section:
    """NCZ section handler"""
    def __init__(self, f):
        self.f = f
        self.offset = read_int64(f)
        self.size = read_int64(f)
        self.cryptoType = read_int64(f)
        read_int64(f)  # padding
        self.cryptoKey = f.read(16)
        self.cryptoCounter = f.read(16)

def decompress_ncz_custom(input_path, output_path):
    """Custom NCZ decompression implementation"""
    try:
        with open(input_path, 'rb') as f:
            # Read header and section info
            header = f.read(0x4000)
            magic = read_int64(f)
            section_count = read_int64(f)
            sections = [Section(f) for _ in range(section_count)]
                
            # Decompress main data
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.stream_reader(f)
                
            with open(output_path, 'wb+') as o:
                o.write(header)
                
                # Stream decompressed data
                while True:
                    chunk = reader.read(16384)
                    if not chunk:
                        break
                    o.write(chunk)
                    
                # Process encrypted sections
                for section in sections:
                    if section.cryptoType == 1:  # plain text
                        continue
                        
                    if section.cryptoType != 3:
                        raise IOError(f'Unknown crypto type: {section.cryptoType}')
                        
                    print(f'{section.offset:x} - {section.size} bytes, type {section.cryptoType}')
                    
                    crypto = AESCTR(section.cryptoKey, section.cryptoCounter)
                    _decrypt_section(o, crypto, section.offset, section.size)
        return True
    except Exception as e:
        print(f"Error decompressing NCZ {input_path}: {e}")
        return False

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

# File parsing utilities
def ret_nsp_offsets(filepath, kbsize=8):
    """Parse NSP file offsets"""
    return _parse_pfs0_offsets(filepath, kbsize, 0, PFS0_ENTRY_SIZE, 'NSP')

def _parse_pfs0_offsets(filepath, kbsize, base_offset, entry_size, file_type):
    """Generic PFS0 offset parser"""
    kbsize = int(kbsize)
    files_list = []
    try:
        with open(filepath, 'r+b') as f:
            f.seek(base_offset)
            data = f.read(int(kbsize * 1024))
        
        if len(data) < 16 or data[0:4] != b'PFS0':
            return files_list
            
        try:
            n_files = int.from_bytes(data[4:8], byteorder='little')
            st_size = int.from_bytes(data[8:12], byteorder='little')
            
            string_table_offset = 0x10 + n_files * entry_size
            string_table = data[string_table_offset:string_table_offset + st_size]
            header_size = string_table_offset + st_size
            string_end_offset = st_size
            
            for i in range(n_files):
                idx = n_files - i - 1
                pos = 0x10 + idx * entry_size
                
                if pos + entry_size > len(data):
                    break
                    
                offset = int.from_bytes(data[pos:pos + 8], byteorder='little')
                size = int.from_bytes(data[pos + 8:pos + 16], byteorder='little')
                name_offset = int.from_bytes(data[pos + 16:pos + 20], byteorder='little')
                
                if name_offset < string_end_offset:
                    name = string_table[name_offset:string_end_offset].decode('utf-8').rstrip(' \t\r\n\0')
                    string_end_offset = name_offset
                    
                    file_start = base_offset + header_size + offset
                    file_end = file_start + size
                    files_list.append([name, file_start, file_end, size])
                    
            files_list.reverse()
        except Exception as e:
            print(f'Exception parsing {file_type}: {e}')
    except Exception as e:
        print(f'Exception reading {file_type}: {e}')
    return files_list

def ret_xci_offsets(filepath, kbsize=8):
    """Parse XCI file offsets"""
    try:
        with open(filepath, 'r+b') as f:
            # Read XCI header to find secure partition offset
            f.seek(0x100)
            magic = f.read(4)
            if magic != b'HEAD':
                return []
                
            secure_offset = int.from_bytes(f.read(4), byteorder='little') * 0x200
            
            # Parse secure partition as HFS0
            return _parse_hfs0_offsets(filepath, kbsize, secure_offset, 'XCI')
    except Exception as e:
        print(f'Exception reading XCI: {e}')
        return []

def _parse_hfs0_offsets(filepath, kbsize, base_offset, file_type):
    """Parse HFS0 partition offsets"""
    kbsize = int(kbsize)
    files_list = []
    try:
        with open(filepath, 'r+b') as f:
            f.seek(base_offset)
            data = f.read(int(kbsize * 1024))
            
        if len(data) < 16 or data[0:4] != b'HFS0':
            return files_list
            
        try:
            n_files = int.from_bytes(data[4:8], byteorder='little')
            st_size = int.from_bytes(data[8:12], byteorder='little')
            
            string_table_offset = 0x10 + n_files * HFS0_ENTRY_SIZE
            string_table = data[string_table_offset:string_table_offset + st_size]
            header_size = string_table_offset + st_size
            string_end_offset = st_size
            
            for i in range(n_files):
                idx = n_files - i - 1
                pos = 0x10 + idx * HFS0_ENTRY_SIZE
                
                if pos + HFS0_ENTRY_SIZE > len(data):
                    break
                    
                offset = int.from_bytes(data[pos:pos + 8], byteorder='little')
                size = int.from_bytes(data[pos + 8:pos + 16], byteorder='little')
                name_offset = int.from_bytes(data[pos + 16:pos + 20], byteorder='little')
                
                if name_offset < string_end_offset:
                    name = string_table[name_offset:string_end_offset].decode('utf-8').rstrip(' \t\r\n\0')
                    string_end_offset = name_offset
                    
                    file_start = base_offset + header_size + offset
                    file_end = file_start + size
                    files_list.append([name, file_start, file_end, size])
                    
            files_list.reverse()
        except Exception as e:
            print(f'Exception parsing {file_type}: {e}')
    except Exception as e:
        print(f'Exception reading {file_type}: {e}')
    return files_list

def gen_nsp_header(files, file_sizes):
    """Generate NSP header"""
    return _gen_pfs0_header(files, file_sizes, 0x10)

def _gen_pfs0_header(files, file_sizes, alignment):
    """Generate PFS0 header with specified alignment"""
    files_nb = len(files)
    string_table = '\x00'.join(str(nca) for nca in files)
    header_size = 0x10 + files_nb * PFS0_ENTRY_SIZE + len(string_table)
    remainder = alignment - (header_size % alignment) if header_size % alignment != 0 else 0
    header_size += remainder
    
    file_offsets = [sum(file_sizes[:n]) for n in range(files_nb)]
    file_names_lengths = [len(str(nca)) + 1 for nca in files]  # +1 for the \x00
    string_table_offsets = [sum(file_names_lengths[:n]) for n in range(files_nb)]

    header = b'PFS0'
    header += pk('<I', files_nb)
    header += pk('<I', len(string_table) + remainder)
    header += b'\x00\x00\x00\x00'
    
    for n in range(files_nb):
        header += pk('<Q', file_offsets[n])
        header += pk('<Q', file_sizes[n])
        header += pk('<I', string_table_offsets[n])
        header += b'\x00\x00\x00\x00'
        
    header += string_table.encode()
    header += remainder * b'\x00'
    return header

def copy_file_content(src_path, dst_file, offset, size, buffer_size=BUFFER_SIZE):
    """Copy file content from source to destination"""
    with open(src_path, 'rb') as src:
        src.seek(offset)
        remaining = size
        
        while remaining > 0:
            chunk_size = min(buffer_size, remaining)
            chunk = src.read(chunk_size)
            if not chunk:
                break
            dst_file.write(chunk)
            remaining -= len(chunk)

def get_xciheader(oflist, osizelist, sec_hashlist):
    """Generate XCI header (simplified version)"""
    # This is a simplified version - full implementation would be much more complex
    upd_list = []
    upd_fileSizes = []
    norm_list = []
    norm_fileSizes = []
    sec_list = oflist
    sec_fileSizes = osizelist
    sec_shalist = sec_hashlist
    
    # Generate simplified HFS0 headers
    def gen_hfs0_header(files, sizes):
        if not files:
            return b'\x00' * 0x30, 0
        
        filesNb = len(files)
        stringTable = '\x00'.join(str(f) for f in files)
        headerSize = 0x10 + filesNb * 0x40 + len(stringTable)
        remainder = 0x200 - (headerSize % 0x200) if headerSize % 0x200 != 0 else 0
        headerSize += remainder
        
        fileOffsets = [sum(sizes[:n]) for n in range(filesNb)]
        fileNamesLengths = [len(str(f)) + 1 for f in files]
        stringTableOffsets = [sum(fileNamesLengths[:n]) for n in range(filesNb)]
        
        header = b'HFS0'
        header += pk('<I', filesNb)
        header += pk('<I', len(stringTable) + remainder)
        header += b'\x00\x00\x00\x00'
        
        for n in range(filesNb):
            header += pk('<Q', fileOffsets[n])
            header += pk('<Q', sizes[n])
            header += pk('<I', stringTableOffsets[n])
            header += b'\x00' * 0x14  # Hash and padding
        
        header += stringTable.encode()
        header += remainder * b'\x00'
        
        return header, headerSize
    
    # Generate partition headers
    upd_header, upd_size = gen_hfs0_header(upd_list, upd_fileSizes)
    norm_header, norm_size = gen_hfs0_header(norm_list, norm_fileSizes)
    sec_header, sec_size = gen_hfs0_header(sec_list, sec_fileSizes)
    
    # Root HFS0 header
    root_files = []
    root_sizes = []
    if upd_size > 0:
        root_files.append('update')
        root_sizes.append(upd_size)
    if norm_size > 0:
        root_files.append('normal')
        root_sizes.append(norm_size)
    if sec_size > 0:
        root_files.append('secure')
        root_sizes.append(sec_size)
    
    root_header, rootSize = gen_hfs0_header(root_files, root_sizes)
    
    # XCI main header components
    signature = bytes.fromhex(randhex(0x100))
    
    # Calculate total size
    tot_size = 0xF000 + rootSize + sum(root_sizes)
    
    # XCI header fields
    sec_offset = (0xF000 + rootSize + upd_size + norm_size) // 0x200
    back_offset = 0xFFFFFFFF
    
    # Generate XCI header
    xci_header = signature  # 0x100 bytes
    xci_header += b'HEAD'  # magic
    xci_header += sec_offset.to_bytes(4, 'little')  # secure offset
    xci_header += back_offset.to_bytes(4, 'little')  # backup offset
    xci_header += b'\x00'  # kek index
    xci_header += b'\x00'  # card size
    xci_header += b'\x00'  # header version
    xci_header += b'\x00'  # flags
    xci_header += (0x8750F4C0A9C5A966).to_bytes(8, 'big')  # package id
    xci_header += ((tot_size - 1) // 0x200).to_bytes(8, 'little')  # valid data end
    xci_header += b'\x00' * 0x10  # info IV
    xci_header += (0xF000).to_bytes(8, 'little')  # HFS0 offset
    xci_header += rootSize.to_bytes(8, 'little')  # HFS0 header size
    xci_header += b'\x00' * 0x20  # HFS0 header hash
    xci_header += b'\x00' * 0x20  # HFS0 initial data hash
    xci_header += b'\x00' * 4  # secure mode
    xci_header += b'\x00' * 4  # title key flag
    xci_header += b'\x00' * 4  # key flag
    xci_header += b'\x00' * 4  # normal area end
    
    # Pad to 0x200
    xci_header += b'\x00' * (0x200 - len(xci_header))
    
    # Game info and other components (simplified)
    game_info = b'\x00' * 0x70
    sig_padding = b'\x00' * (0x7000 - 0x200 - 0x70)
    xci_certificate = b'\x00' * 0x200
    
    # Pad to 0xF000
    padding_size = 0xF000 - len(xci_header) - len(game_info) - len(sig_padding) - len(xci_certificate)
    if padding_size > 0:
        sig_padding += b'\x00' * padding_size
    
    return (xci_header, game_info, sig_padding, xci_certificate, 
            root_header, upd_header, norm_header, sec_header, 
            rootSize, 1, 1, 1)

# Minimal file format handlers
class MinimalNSP:
    """NSP file handler"""
    def __init__(self, filepath):
        self.filepath = filepath
        self.files = []
        self._parse_header()
    
    def _parse_header(self):
        """Parse NSP header to get file list"""
        with open(self.filepath, 'rb') as file_handle:
            # Read PFS0 header
            magic = file_handle.read(4)
            if magic != b'PFS0':
                raise ValueError("Invalid NSP file")
            
            file_count = struct.unpack('<I', file_handle.read(4))[0]
            string_table_size = struct.unpack('<I', file_handle.read(4))[0]
            file_handle.read(4)  # Reserved
            
            # Read file entries
            for i in range(file_count):
                offset = struct.unpack('<Q', file_handle.read(8))[0]
                size = struct.unpack('<Q', file_handle.read(8))[0]
                name_offset = struct.unpack('<I', file_handle.read(4))[0]
                file_handle.read(4)  # Reserved
                
                # Store current position
                current_pos = file_handle.tell()
                
                # Read filename
                file_handle.seek(0x10 + file_count * 0x18 + name_offset)
                name = b''
                while True:
                    char = file_handle.read(1)
                    if char == b'\x00' or not char:
                        break
                    name += char
                
                # Try different encodings to handle various file name formats
                try:
                    decoded_name = name.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        decoded_name = name.decode('latin-1')
                    except UnicodeDecodeError:
                        # Fallback: replace invalid characters
                        decoded_name = name.decode('utf-8', errors='replace')
                
                self.files.append({
                    'name': decoded_name,
                    'offset': 0x10 + file_count * 0x18 + string_table_size + offset,
                    'size': size
                })
                
                # Restore position
                file_handle.seek(current_pos)
    
    def get_cnmt_content_sizes(self):
        """Extract actual content sizes from CNMT metadata"""
        content_sizes = {}
        
        # Find CNMT file
        cnmt_file = None
        for file_entry in self.files:
            if file_entry['name'].endswith('.cnmt.nca'):
                cnmt_file = file_entry
                break
        
        if not cnmt_file:
            return content_sizes
        
        try:
            # Use simplified approach - read the CNMT NCA directly and parse its structure
            with open(self.filepath, 'rb') as file_handle:
                # Seek to CNMT NCA
                file_handle.seek(cnmt_file['offset'])
                
                # Read entire CNMT NCA into memory for easier parsing
                nca_data = file_handle.read(cnmt_file['size'])
                
                # Check NCA magic at different offsets
                nca_magic_0 = nca_data[0x0:0x4] if len(nca_data) >= 4 else b''
                nca_magic_200 = nca_data[0x200:0x204] if len(nca_data) >= 0x204 else b''
                
                # Determine if NCA is encrypted or not
                is_encrypted = False
                nca_header_offset = 0
                
                if nca_magic_0 in [b'NCA3', b'NCA2']:
                    nca_header_offset = 0
                elif nca_magic_200 in [b'NCA3', b'NCA2']:
                    is_encrypted = True
                    nca_header_offset = 0x200
                else:
                    # Sometimes the CNMT data might be directly accessible
                    return self._parse_raw_cnmt_data(nca_data)
                
                if is_encrypted:
                    return content_sizes
                
                # Parse unencrypted NCA structure
                if len(nca_data) < nca_header_offset + 0x400:
                    return content_sizes
                
                # Get section 0 info (contains PFS0 with CNMT)
                section_table_offset = nca_header_offset + 0x240
                if len(nca_data) < section_table_offset + 0x20:
                    return content_sizes
                
                section_offset = struct.unpack('<Q', nca_data[section_table_offset:section_table_offset + 8])[0]
                section_size = struct.unpack('<Q', nca_data[section_table_offset + 8:section_table_offset + 16])[0]
                
                if section_offset == 0 or section_size == 0:
                    return content_sizes
                
                # Calculate PFS0 offset within NCA
                pfs0_offset = nca_header_offset + 0x400 + section_offset
                
                if len(nca_data) < pfs0_offset + 16:
                    return content_sizes
                
                # Parse PFS0 header
                pfs0_magic = nca_data[pfs0_offset:pfs0_offset + 4]
                
                if pfs0_magic != b'PFS0':
                    return content_sizes
                
                file_count = struct.unpack('<I', nca_data[pfs0_offset + 4:pfs0_offset + 8])[0]
                string_table_size = struct.unpack('<I', nca_data[pfs0_offset + 8:pfs0_offset + 12])[0]
                
                # Find CNMT file within PFS0
                cnmt_entry = None
                for i in range(file_count):
                    entry_offset = pfs0_offset + 0x10 + i * 0x18
                    if len(nca_data) < entry_offset + 0x18:
                        break
                    
                    file_offset = struct.unpack('<Q', nca_data[entry_offset:entry_offset + 8])[0]
                    file_size = struct.unpack('<Q', nca_data[entry_offset + 8:entry_offset + 16])[0]
                    name_offset = struct.unpack('<I', nca_data[entry_offset + 16:entry_offset + 20])[0]
                    
                    # Read filename
                    name_start = pfs0_offset + 0x10 + file_count * 0x18 + name_offset
                    if len(nca_data) <= name_start:
                        continue
                    
                    filename = b''
                    for j in range(name_start, len(nca_data)):
                        if nca_data[j] == 0:
                            break
                        filename += bytes([nca_data[j]])
                    
                    filename_str = filename.decode('utf-8', errors='ignore')
                    
                    if filename_str.endswith('.cnmt'):
                        cnmt_entry = {
                            'offset': pfs0_offset + 0x10 + file_count * 0x18 + string_table_size + file_offset,
                            'size': file_size,
                            'name': filename_str
                        }
                        break
                
                if not cnmt_entry:
                    return content_sizes
                
                # Extract and parse CNMT data
                if len(nca_data) < cnmt_entry['offset'] + cnmt_entry['size']:
                    return content_sizes
                
                cnmt_data = nca_data[cnmt_entry['offset']:cnmt_entry['offset'] + cnmt_entry['size']]
                
                return self._parse_cnmt_data(cnmt_data)
                
        except Exception:
            return content_sizes
    
    def _parse_raw_cnmt_data(self, data):
        """Try to parse data directly as CNMT"""
        content_sizes = {}
        try:
            
            # Look for CNMT signature patterns
            for offset in range(0, min(len(data), 0x1000), 0x10):
                if len(data) < offset + 0x20:
                    continue
                
                # Try to parse as CNMT header
                title_id = struct.unpack('<Q', data[offset:offset + 8])[0]
                if title_id == 0:
                    continue
                
                content_count = struct.unpack('<H', data[offset + 0x0E:offset + 0x10])[0]
                if content_count == 0 or content_count > 100:  # Reasonable limit
                    continue
                
                # Try to parse content entries
                extended_header_size = struct.unpack('<H', data[offset + 0x14:offset + 0x16])[0] if len(data) >= offset + 0x16 else 0
                content_entries_offset = offset + 0x20 + extended_header_size
                
                parsed_entries = 0
                for i in range(content_count):
                    entry_offset = content_entries_offset + i * 0x38
                    if entry_offset + 0x38 > len(data):
                        break
                    
                    nca_id = data[entry_offset + 0x20:entry_offset + 0x30].hex()
                    content_size = struct.unpack('<Q', data[entry_offset + 0x30:entry_offset + 0x38])[0] & 0xFFFFFFFFFFFF
                    content_type = data[entry_offset + 0x36]
                    
                    if content_size > 0 and len(nca_id) == 32:  # Valid NCA ID
                        if content_type == 0:
                            content_sizes[nca_id + '.cnmt.nca'] = content_size
                        else:
                            content_sizes[nca_id + '.nca'] = content_size
                        parsed_entries += 1
                
                if parsed_entries > 0:
                    return content_sizes
                    
        except Exception:
                pass
        
        return content_sizes
    
    def _parse_cnmt_data(self, cnmt_data):
        """Parse CNMT data structure following Nsp.py approach"""
        content_sizes = {}
        
        if len(cnmt_data) < 0x20:
            return content_sizes
        
        try:
            # Parse CNMT header (following Nsp.py structure)
            content_count = struct.unpack('<H', cnmt_data[0x0E:0x10])[0]
            
            if content_count == 0 or content_count > 100:  # Sanity check
                return content_sizes
            
            # Get extended header size and calculate content entries offset
            extended_header_size = struct.unpack('<H', cnmt_data[0x14:0x16])[0] if len(cnmt_data) >= 0x16 else 0
            content_entries_offset = 0x20 + extended_header_size
            
            # Parse content entries (following Nsp.py structure)
            for i in range(content_count):
                entry_offset = content_entries_offset + i * 0x38
                if entry_offset + 0x38 > len(cnmt_data):
                    break
                
                # Read content entry structure
                nca_id = cnmt_data[entry_offset + 0x20:entry_offset + 0x30].hex()  # 16 bytes NCA ID
                size_bytes = cnmt_data[entry_offset + 0x30:entry_offset + 0x36]  # 6 bytes size
                content_type = cnmt_data[entry_offset + 0x36]  # 1 byte type
                
                # Parse 6-byte size (little endian)
                content_size = struct.unpack('<Q', size_bytes + b'\x00\x00')[0]
                
                # Map content type to filename (following Nsp.py approach)
                if content_type == 0:  # Meta
                    filename = nca_id + '.cnmt.nca'
                else:  # Program, Data, Control, etc.
                    filename = nca_id + '.nca'
                
                content_sizes[filename] = content_size
            
            return content_sizes
            
        except Exception:
            return content_sizes

class MinimalXCI:
    """Minimal XCI file handler"""
    def __init__(self, filepath):
        self.filepath = filepath
        self.files = []
        self._parse_header()
    
    def _parse_header(self):
        """Parse XCI header to get basic info"""
        with open(self.filepath, 'rb') as file_handle:
            # Read XCI header
            magic = file_handle.read(4)
            if magic != b'HEAD':
                raise ValueError("Invalid XCI file")
            
            # Skip to HFS0 root partition at 0xF000
            file_handle.seek(0xF000)
            
            # Read HFS0 header
            magic = file_handle.read(4)
            if magic != b'HFS0':
                return  # No valid HFS0 partition
            
            file_count = struct.unpack('<I', file_handle.read(4))[0]
            string_table_size = struct.unpack('<I', file_handle.read(4))[0]
            file_handle.read(4)  # Reserved
            
            # Read partition entries (update, normal, secure)
            for i in range(file_count):
                offset = struct.unpack('<Q', file_handle.read(8))[0]
                size = struct.unpack('<Q', file_handle.read(8))[0]
                name_offset = struct.unpack('<I', file_handle.read(4))[0]
                file_handle.read(4)  # Reserved
                
                # Store current position
                current_pos = file_handle.tell()
                
                # Read partition name
                file_handle.seek(0xF000 + 0x10 + file_count * 0x20 + name_offset)
                name = b''
                while True:
                    char = file_handle.read(1)
                    if char == b'\x00' or not char:
                        break
                    name += char
                
                self.files.append({
                    'name': name.decode('utf-8'),
                    'offset': 0xF000 + 0x10 + file_count * 0x20 + string_table_size + offset,
                    'size': size
                })
                
                # Restore position
                file_handle.seek(current_pos)

def decompress_nsz(input_path, output_path, buffer_size=65536):
    """Decompress NSZ to NSP using custom decompressor"""
    try:
        print(f"Decompressing NSZ: {input_path} -> {output_path}")
        
        # Parse NSP file structure
        files_list = ret_nsp_offsets(input_path)
        if not files_list:
            print("Failed to parse NSP structure")
            return False
        
        # Extract file information
        nca_files = []
        file_sizes = []
        temp_files = []
        
        with open(input_path, 'rb') as f:
            for file_info in files_list:
                name, start_offset, end_offset, size = file_info
                
                if name.endswith('.ncz'):
                    # Decompress NCZ to temporary NCA
                    temp_ncz = tempfile.NamedTemporaryFile(delete=False, suffix='.ncz')
                    temp_ncz.close()
                    temp_files.append(temp_ncz.name)
                    
                    # Extract NCZ data
                    f.seek(start_offset)
                    ncz_data = f.read(size)
                    
                    with open(temp_ncz.name, 'wb') as temp_f:
                        temp_f.write(ncz_data)
                    
                    # Decompress NCZ
                    temp_nca = tempfile.NamedTemporaryFile(delete=False, suffix='.nca')
                    temp_nca.close()
                    temp_files.append(temp_nca.name)
                    
                    if decompress_ncz_custom(temp_ncz.name, temp_nca.name):
                        # Get decompressed size
                        decompressed_size = os.path.getsize(temp_nca.name)
                        nca_files.append((name.replace('.ncz', '.nca'), temp_nca.name, decompressed_size, True))
                        file_sizes.append(decompressed_size)
                    else:
                        print(f"Failed to decompress {name}")
                        cleanup_temp_files(temp_files)
                        return False
                else:
                    # Regular file (NCA, etc.)
                    nca_files.append((name, None, size, False))
                    file_sizes.append(size)
        
        # Generate NSP header
        file_names = [info[0] for info in nca_files]
        header = gen_nsp_header(file_names, file_sizes)
        
        # Write decompressed NSP
        with open(output_path, 'wb') as out_f:
            out_f.write(header)
            
            # Write file data
            with open(input_path, 'rb') as in_f:
                for i, (name, temp_path, size, is_decompressed) in enumerate(nca_files):
                    if is_decompressed and temp_path:  # Decompressed NCZ
                        with open(temp_path, 'rb') as temp_f:
                            while True:
                                chunk = temp_f.read(buffer_size)
                                if not chunk:
                                    break
                                out_f.write(chunk)
                    else:  # Regular file
                        file_info = files_list[i]
                        start_offset = file_info[1]
                        copy_file_content(input_path, out_f, start_offset, size, buffer_size)
        
        # Cleanup temporary files
        cleanup_temp_files(temp_files)
        
        print(f"NSZ decompression completed: {output_path}")
        return True
        
    except Exception as e:
        print(f"Error decompressing NSZ {input_path}: {e}")
        return False

def decompress_xcz(input_path, output_path, buffer_size=65536):
    """Decompress XCZ to XCI using custom decompressor"""
    try:
        print(f"Decompressing XCZ: {input_path} -> {output_path}")
        
        # Parse XCI file structure
        files_list = ret_xci_offsets(input_path)
        if not files_list:
            print("Failed to parse XCI structure")
            return False
        
        # Extract file information
        nca_files = []
        file_sizes = []
        sec_hashlist = []
        temp_files = []
        
        with open(input_path, 'rb') as f:
            for file_info in files_list:
                name, start_offset, end_offset, size = file_info
                
                if name.endswith('.ncz'):
                    # Decompress NCZ to temporary NCA
                    temp_ncz = tempfile.NamedTemporaryFile(delete=False, suffix='.ncz')
                    temp_ncz.close()
                    temp_files.append(temp_ncz.name)
                    
                    # Extract NCZ data
                    f.seek(start_offset)
                    ncz_data = f.read(size)
                    
                    with open(temp_ncz.name, 'wb') as temp_f:
                        temp_f.write(ncz_data)
                    
                    # Decompress NCZ
                    temp_nca = tempfile.NamedTemporaryFile(delete=False, suffix='.nca')
                    temp_nca.close()
                    temp_files.append(temp_nca.name)
                    
                    if decompress_ncz_custom(temp_ncz.name, temp_nca.name):
                        # Get decompressed size
                        decompressed_size = os.path.getsize(temp_nca.name)
                        nca_files.append((name.replace('.ncz', '.nca'), temp_nca.name, decompressed_size, True))
                        file_sizes.append(decompressed_size)
                        sec_hashlist.append(b'\x00' * 0x20)  # Placeholder hash
                    else:
                        print(f"Failed to decompress {name}")
                        cleanup_temp_files(temp_files)
                        return False
                else:
                    # Regular file (NCA, etc.)
                    nca_files.append((name, None, size, False))
                    file_sizes.append(size)
                    sec_hashlist.append(b'\x00' * 0x20)  # Placeholder hash
        
        # Generate XCI header
        file_names = [info[0] for info in nca_files]
        header_components = get_xciheader(file_names, file_sizes, sec_hashlist)
        
        # Write decompressed XCI
        with open(output_path, 'wb') as out_f:
            # Write XCI header components
            for component in header_components[:8]:  # First 8 components are headers
                out_f.write(component)
            
            # Write file data
            with open(input_path, 'rb') as in_f:
                for i, (name, temp_path, size, is_decompressed) in enumerate(nca_files):
                    if is_decompressed and temp_path:  # Decompressed NCZ
                        with open(temp_path, 'rb') as temp_f:
                            while True:
                                chunk = temp_f.read(buffer_size)
                                if not chunk:
                                    break
                                out_f.write(chunk)
                    else:  # Regular file
                        file_info = files_list[i]
                        start_offset = file_info[1]
                        copy_file_content(input_path, out_f, start_offset, size, buffer_size)
        
        # Cleanup temporary files
        cleanup_temp_files(temp_files)
        
        print(f"XCZ decompression completed: {output_path}")
        return True
        
    except Exception as e:
        print(f"Error decompressing XCZ {input_path}: {e}")
        return False

def main():
    """Main entry point for the application"""
    parser = _create_argument_parser()
    args = parser.parse_args()
    
    try:
        if args.decompress:
            return handle_decompression(args)
        elif args.direct_creation:
            return handle_direct_creation(args)
        elif args.direct_multi:
            return handle_direct_multi(args)
        else:
            parser.print_help()
            return 0
            
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        return 1

def _create_argument_parser():
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description='Standalone Squirrel - NSP/XCI repackaging and NSZ/XCZ decompression'
    )
    
    # Core arguments
    parser.add_argument('file', nargs='*', help='Input files')
    parser.add_argument('-dc', '--direct_creation', nargs='+', help='Create directly a nsp or xci')
    parser.add_argument('-dmul', '--direct_multi', nargs='+', help='Create directly a multi nsp or xci')
    parser.add_argument('-dcpr', '--decompress', help='Decompress a nsz, xcz or ncz')
    
    # Options
    parser.add_argument('-o', '--ofolder', nargs='+', help='Set output folder')
    parser.add_argument('-tfile', '--text_file', help='Input text file with file list')
    parser.add_argument('-b', '--buffer', type=int, default=BUFFER_SIZE, help='Set buffer size')
    parser.add_argument('-t', '--type', default='xci', help='Set output type (xci only - NSP/NSZ inputs convert to XCI)')
    parser.add_argument('-fat', '--fat', default='exfat', help='Set FAT format (fat32, exfat)')
    parser.add_argument('-fx', '--fexport', default='files', help='Export format (files, folder)')
    parser.add_argument('-ND', '--nodelta', action='store_true', default=True, help='Disable delta fragments')
    parser.add_argument('-pv', '--patchversion', default='0', help='Patch version')
    parser.add_argument('-kp', '--keypatch', default='False', help='Key patch')
    parser.add_argument('-rsvc', '--RSVcap', type=int, default=268435656, help='RSV capacity')
    parser.add_argument('-roma', '--romanize', action='store_true', default=True, help='Romanize names')
    parser.add_argument('-rn', '--rename', help='Rename output file')
    
    return parser

def get_output_folder(args):
    """Get output folder from args or create default"""
    if args.ofolder:
        ofolder = args.ofolder[0] if isinstance(args.ofolder, list) else args.ofolder
    else:
        ofolder = os.path.join(os.getcwd(), 'output')
    
    os.makedirs(ofolder, exist_ok=True)
    return ofolder

def get_input_file(text_file, direct_file):
    """Get input file from text file or direct argument"""
    if text_file:
        with open(text_file, 'r', encoding='utf8') as file_handle:
            return os.path.abspath(file_handle.readline().strip())
    return direct_file

def get_file_list(text_file):
    """Get list of existing files from text file"""
    file_list = []
    try:
        with open(text_file, 'r') as file_handle:
            for line in file_handle:
                line = line.strip()
                if line and not line.startswith('#') and os.path.exists(line):
                    file_list.append(line)
                elif line and not line.startswith('#'):
                    pass
    except Exception:
        pass
    return file_list

def decompress_file(filepath, buffer_size=65536):
    """Decompress a single file and return the decompressed path"""
    if not filepath.endswith(('.nsz', '.xcz', '.ncz')):
        return filepath  # Already decompressed
    
    temp_dir = tempfile.mkdtemp()
    basename = os.path.basename(filepath)
    
    if filepath.endswith('.nsz'):
        temp_file = os.path.join(temp_dir, basename[:-1] + 'p')  # .nsz -> .nsp
        decompress_nsz(filepath, temp_file, buffer_size)
    elif filepath.endswith('.xcz'):
        temp_file = os.path.join(temp_dir, basename[:-3] + 'xci')  # .xcz -> .xci
        decompress_xcz(filepath, temp_file, buffer_size)
    elif filepath.endswith('.ncz'):
        temp_file = os.path.join(temp_dir, basename[:-1] + 'a')  # .ncz -> .nca
        if decompress_ncz_custom(filepath, temp_file):
            return temp_file
        else:
            return filepath
    
    return temp_file

def analyze_file_content(filepath):
    """Analyze file content and return content list"""
    content_list = []
    try:
        if filepath.endswith('.nsp'):
            nsp = MinimalNSP(filepath)
            for file_entry in nsp.files:
                content_list.append([file_entry['name'], file_entry['size']])
        elif filepath.endswith('.xci'):
            xci = MinimalXCI(filepath)
            for file_entry in xci.files:
                content_list.append([file_entry['name'], file_entry['size']])
        elif filepath.endswith('.nca'):
            file_size = os.path.getsize(filepath)
            content_list = [[os.path.basename(filepath), file_size]]
        
        # If no content found, add the file itself
        if not content_list:
            file_size = os.path.getsize(filepath)
            content_list = [[os.path.basename(filepath), file_size]]
            
    except Exception:
        # Fallback: add the file itself
        try:
            file_size = os.path.getsize(filepath)
            content_list = [[os.path.basename(filepath), file_size]]
        except:
            pass
    
    return content_list

def cleanup_temp_files(temp_files):
    """Clean up temporary files and directories"""
    if not temp_files:
        return
        
    for temp_file in temp_files:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            # Remove empty temp directory
            temp_dir = os.path.dirname(temp_file)
            if os.path.exists(temp_dir) and not os.listdir(temp_dir):
                os.rmdir(temp_dir)
        except Exception:
            pass  # Silently handle cleanup errors

def handle_decompression(args):
    """Handle NSZ/XCZ/NCZ decompression"""
    # Get output folder
    ofolder = get_output_folder(args)
    
    # Get input file
    filepath = get_input_file(args.text_file, args.decompress)
    
    # Decompress based on file extension
    basename = os.path.basename(filepath)
    
    if filepath.endswith(".nsz"):
        outfile = os.path.join(ofolder, basename[:-1] + 'p')  # .nsz -> .nsp
        success = decompress_nsz(filepath, outfile, args.buffer)
    elif filepath.endswith(".xcz"):
        outfile = os.path.join(ofolder, basename[:-3] + 'xci')  # .xcz -> .xci
        success = decompress_xcz(filepath, outfile, args.buffer)
    elif filepath.endswith(".ncz"):
        outfile = os.path.join(ofolder, basename[:-1] + 'a')  # .ncz -> .nca
        success = decompress_ncz_custom(filepath, outfile)
    else:
        raise ValueError(f"Unsupported file type: {filepath}")
    
    return 0 if success else 1

def handle_direct_creation(args):
    """Handle NSP/XCI direct creation (repackaging)"""
    return 1

def handle_direct_multi(args):
    """Handle direct multi creation (-dmul)"""
    if len(args.direct_multi) < 1:
        return 1
    
    # Get file list from text file or direct arguments
    if args.text_file:
        file_list = get_file_list(args.text_file)
        if not file_list:
            return 1
    else:
        # Use files passed directly as arguments
        file_list = [f for f in args.direct_multi if os.path.exists(f)]
        if not file_list:
            print("No valid input files found")
            return 1
    
    # Default export type is XCI
    export_type = 'xci'
    
    # Get output folder
    ofolder = get_output_folder(args)
    output_file = os.path.join(ofolder, f'Multi_Content.{export_type.lower()}')
    
    try:
        # Create multi-XCI package (NSP/NSZ inputs convert to XCI output)
        success = create_multi_xci(file_list, output_file, args)
        
        return 0 if success else 1
    finally:
        pass

# NSP output functionality removed - all inputs convert to XCI format

def set_nca_gamecard_flag(nca_path):
    """Set gamecard flag in NCA header for XCI compatibility (critical for emulators)"""
    try:
        with open(nca_path, 'r+b') as file_handle:
            # Read NCA header to check current gamecard flag
            file_handle.seek(0x204)  # isGameCard flag location
            current_flag = file_handle.read(1)
            
            if current_flag == b'\x00':  # If not set as gamecard
                file_handle.seek(0x204)
                file_handle.write(b'\x01')  # Set as gamecard
                file_handle.flush()
            else:
                pass
                
    except Exception:
        pass

def create_multi_xci(file_list, outfile, args):
    """Create multi-XCI file with unified progress tracking using proper size calculations"""
    try:
        # Calculate original size
        original_size = sum(os.path.getsize(f) for f in file_list if os.path.exists(f))
        
        # Phase 1: Decompression
        processed_files = []
        temp_files = []
        
        for i, filepath in enumerate(file_list):
            processed_file = decompress_file(filepath, args.buffer)
            processed_files.append(processed_file)
            if processed_file != filepath:
                temp_files.append(processed_file)
            
        # Calculate decompressed size
        decompressed_size = sum(os.path.getsize(f) for f in processed_files if os.path.exists(f))
    
        # Phase 2: Content Analysis with proper NCA size calculation
        all_files = []
        all_sizes = []
        
        for i, filepath in enumerate(processed_files):
            if filepath.endswith('.nsp'):
                # For NSP files, extract NCA files and use CNMT content sizes (like original NSC_Builder)
                try:
                    nsp = MinimalNSP(filepath)
                    content_sizes = nsp.get_cnmt_content_sizes()
                except Exception:
                    content_sizes = {}
                
                for file_entry in nsp.files:
                    if file_entry['name'].endswith('.nca'):
                        all_files.append(file_entry['name'])
                        # Use actual content size from CNMT metadata (critical for proper XCI structure)
                        if file_entry['name'] in content_sizes:
                            actual_size = content_sizes[file_entry['name']]
                            all_sizes.append(actual_size)
                        else:
                            # Fallback to file size if not found in CNMT
                            all_sizes.append(file_entry['size'])
            elif filepath.endswith('.nca'):
                # For standalone NCA files, use actual file size (like original NSC_Builder)
                all_files.append(os.path.basename(filepath))
                all_sizes.append(os.path.getsize(filepath))
        
        # Phase 3: XCI Structure Generation (using proven sq_tools algorithm)
        # CRITICAL: Add dummy files when there are fewer than 4 NCAs (matching XCI.bat logic)
        # This is essential for proper XCI structure as shown in original NSC_Builder
        dummy_files_added = []
        if len(all_files) <= 3:
            dummy_files_added.append('0')
            all_files.append('0')
            all_sizes.append(0)
        if len(all_files) <= 3:
            dummy_files_added.append('00')
            all_files.append('00')
            all_sizes.append(0)
        if len(all_files) <= 3:
            dummy_files_added.append('000')
            all_files.append('000')
            all_sizes.append(0)
        
        # Generate proper file hashes for secure partition (CRITICAL for emulator compatibility)
        # Calculate actual SHA256 hashes instead of dummy hashes to fix verification failures
        sec_hashlist = []
        print("Calculating SHA256 hashes for NCA files...")
        for i, filename in enumerate(all_files):
            # Skip dummy files
            if filename in ['0', '00', '000']:
                sha = '0000000000000000000000000000000000000000000000000000000000000000'
                sec_hashlist.append(sha)
                continue
                
            # Calculate actual SHA256 hash for real NCA files
            sha = '0000000000000000000000000000000000000000000000000000000000000000'  # Default fallback
            
            # Find the source file for this NCA
            for filepath in processed_files:
                if filepath.endswith('.nsp'):
                    try:
                        nsp = MinimalNSP(filepath)
                        for file_entry in nsp.files:
                            if file_entry['name'] == filename and file_entry['name'].endswith('.nca'):
                                # Extract first 0x200 bytes and calculate hash
                                with open(filepath, 'rb') as nsp_file:
                                    nsp_file.seek(file_entry['offset'])
                                    header_block = nsp_file.read(0x200)
                                    if len(header_block) == 0x200:
                                        from hashlib import sha256
                                        sha = sha256(header_block).hexdigest()
                                break
                    except Exception:
                        pass
                elif filepath.endswith('.nca') and os.path.basename(filepath) == filename:
                    try:
                        # Calculate hash from first 0x200 bytes of NCA header
                        with open(filepath, 'rb') as nca_file:
                            header_block = nca_file.read(0x200)
                            if len(header_block) == 0x200:
                                from hashlib import sha256
                                sha = sha256(header_block).hexdigest()
                    except Exception:
                        pass
            
            sec_hashlist.append(sha)
            if sha != '0000000000000000000000000000000000000000000000000000000000000000':
                print(f"  {filename}: {sha[:16]}...")

        # Use ztools sq_tools.get_xciheader function for XCI header generation
        xci_header, game_info, sig_padding, xci_certificate, root_header, upd_header, norm_header, sec_header, rootSize, upd_multiplier, norm_multiplier, sec_multiplier = get_xciheader(all_files, all_sizes, sec_hashlist)
        
        # Calculate total size like original
        tot_size = 0xF000 + rootSize
        try:
            with open(outfile, 'wb') as xci_file:
                # Write complete XCI header structure (same as working XCI creation)
                print(f"Writing XCI header to {outfile}...")
                xci_file.write(xci_header)
                xci_file.write(game_info)
                xci_file.write(sig_padding)
                xci_file.write(xci_certificate)
                xci_file.write(root_header)  # Root HFS0 header
                xci_file.write(upd_header)  # Update partition (empty)
                xci_file.write(norm_header)  # Normal partition (empty)
                xci_file.write(sec_header)  # Secure partition header
                print(f"XCI header written successfully, now writing content files...")
                
                # Phase 4: Content Appending (CRITICAL: Must match exact order from all_files list)
                # Create mapping from filename to source file and offset for efficient lookup
                file_mapping = {}
                for filepath in processed_files:
                    if filepath.endswith('.nsp'):
                        nsp = MinimalNSP(filepath)
                        for file_entry in nsp.files:
                            if file_entry['name'].endswith('.nca'):
                                file_mapping[file_entry['name']] = {
                                    'source_file': filepath,
                                    'offset': file_entry['offset'],
                                    'size': file_entry['size'],
                                    'type': 'nsp'
                                }
                    elif filepath.endswith('.nca'):
                        filename = os.path.basename(filepath)
                        file_mapping[filename] = {
                            'source_file': filepath,
                            'offset': 0,
                            'size': os.path.getsize(filepath),
                            'type': 'nca'
                        }
                
                # Append files in the EXACT order specified in all_files (critical for XCI structure)
                for i, filename in enumerate(all_files):
                    # Handle dummy files (skip actual content writing for dummy files)
                    if filename in ['0', '00', '000']:
                        continue
                    
                    if filename not in file_mapping:
                        continue
                        
                    file_info = file_mapping[filename]
                    
                    if file_info['type'] == 'nsp':
                        # Extract NCA from NSP to temp file for gamecard flag validation
                        temp_nca = os.path.join(tempfile.gettempdir(), filename)
                        with open(file_info['source_file'], 'rb') as nsp_file:
                            nsp_file.seek(file_info['offset'])
                            nca_data = nsp_file.read(file_info['size'])
                            with open(temp_nca, 'wb') as nca_file:
                                nca_file.write(nca_data)
                        
                        # Set gamecard flag for XCI compatibility (critical for emulators)
                        try:
                            set_nca_gamecard_flag(temp_nca)
                        except Exception:
                            pass
                        
                        # Copy the modified NCA to output
                        with open(temp_nca, 'rb') as nca_file:
                            while True:
                                buf = nca_file.read(args.buffer)
                                if not buf:
                                    break
                                xci_file.write(buf)
                        
                        # Clean up temp file immediately
                        try:
                            os.remove(temp_nca)
                        except Exception:
                            pass
                            
                    elif file_info['type'] == 'nca':
                        # Direct NCA file - set gamecard flag for XCI compatibility
                        temp_nca = os.path.join(tempfile.gettempdir(), filename)
                        import shutil
                        shutil.copy2(file_info['source_file'], temp_nca)
                        
                        # Set gamecard flag (critical for emulators)
                        try:
                            set_nca_gamecard_flag(temp_nca)
                        except Exception:
                            pass
                        
                        # Copy the modified NCA to output
                        with open(temp_nca, 'rb') as nca_file:
                            while True:
                                chunk = nca_file.read(args.buffer)
                                if not chunk:
                                    break
                                xci_file.write(chunk)
                        
                        # Clean up temp file immediately
                        try:
                            os.remove(temp_nca)
                        except Exception:
                            pass
                
            print(f"XCI file creation completed successfully: {outfile}")
                
        except IOError as e:
            print(f"IO Error writing XCI file: {str(e)}")
            raise
        except OSError as e:
            print(f"OS Error writing XCI file: {str(e)}")
            raise
        
        # Cleanup temp files
        if temp_files:
            cleanup_temp_files(temp_files)
        
        return True
        
    except Exception as e:
        # Print detailed error information for debugging
        print(f"Error creating XCI file: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Ensure temp files are cleaned up even on error
        if 'temp_files' in locals() and temp_files:
            cleanup_temp_files(temp_files)
        return False

def randhex(size):
	hexdigits = "0123456789ABCDEF"
	random_digits = "".join([ hexdigits[random.randint(0,0xF)] for _ in range(size*2) ])
	return random_digits

def getGCsize(bytes_size):
    """Get game card size and firmware version based on file size"""
    gb_size = bytes_size / (1024 * 1024 * 1024)
    gb_size = round(gb_size, 2)
    
    # Define size thresholds and corresponding card types
    size_mappings = [
        (32, 0xE3, '1000a100'),
        (16, 0xE2, '1000a100'),
        (8, 0xE1, '1000a100'),
        (4, 0xE0, '1000a100'),
        (2, 0xF0, '1100a100'),
        (1, 0xF8, '1100a100'),
        (0, 0xFA, '1100a100')  # Default for < 1GB
    ]
    
    for threshold, card, firm_ver in size_mappings:
        if gb_size >= threshold:
            return card, firm_ver
    
    # Fallback (should never reach here)
    return 0xFA, '1100a100'

def get_enc_gameinfo(bytes_size):
    """Generate encrypted game info based on file size"""
    gb_size = bytes_size / (1024 * 1024 * 1024)
    gb_size = round(gb_size, 2)
    
    # Select game info parameters based on size
    if gb_size >= 4:  # Large games (4GB+)
        game_params = {
            'firm_ver': 0x9298F35088F09F7D,
            'access_freq': 0xa89a60d4,
            'read_wait_time': 0xcba6f96f,
            'read_wait_time2': 0xa45bb6ac,
            'write_wait_time': 0xabc751f9,
            'write_wait_time2': 0x5d398742,
            'firmware_mode': 0x6b38c3f2,
            'cup_version': 0x10da0b70,
            'empty1': 0x0e5ece29,
            'upd_hash': 0xa13cbe1da6d052cb,
            'cup_id': 0xf2087ce9af590538,
            'empty2': 0x570d78b9cdd27fbeb4a0ac2adff9ba77754dd6675ac76223506b3bdabcb2e212fa465111ab7d51afc8b5b2b21c4b3f40654598620282add6
        }
    else:  # Small games (< 4GB)
        game_params = {
            'firm_ver': 0x9109FF82971EE993,
            'access_freq': 0x5011ca06,
            'read_wait_time': 0x3f3c4d87,
            'read_wait_time2': 0xa13d28a9,
            'write_wait_time': 0x928d74f1,
            'write_wait_time2': 0x49919eb7,
            'firmware_mode': 0x82e1f0cf,
            'cup_version': 0xe4a5a3bd,
            'empty1': 0xf978295c,
            'upd_hash': 0xd52639a4991bdb1f,
            'cup_id': 0xed841779a3f85d23,
            'empty2': 0xaa4242135616f5187c03cf0d97e5d218fdb245381fd1cf8dfb796fbeda4bf7f7d6b128ce89bc9eaa8552d42f597c5db866c67bb0dd8eea11
        }
    
    # Convert to bytes and build game info
    game_info = b''
    game_info += game_params['firm_ver'].to_bytes(8, byteorder='big')
    game_info += game_params['access_freq'].to_bytes(4, byteorder='big')
    game_info += game_params['read_wait_time'].to_bytes(4, byteorder='big')
    game_info += game_params['read_wait_time2'].to_bytes(4, byteorder='big')
    game_info += game_params['write_wait_time'].to_bytes(4, byteorder='big')
    game_info += game_params['write_wait_time2'].to_bytes(4, byteorder='big')
    game_info += game_params['firmware_mode'].to_bytes(4, byteorder='big')
    game_info += game_params['cup_version'].to_bytes(4, byteorder='big')
    game_info += game_params['empty1'].to_bytes(4, byteorder='big')
    game_info += game_params['upd_hash'].to_bytes(8, byteorder='big')
    game_info += game_params['cup_id'].to_bytes(8, byteorder='big')
    game_info += game_params['empty2'].to_bytes(56, byteorder='big')
    
    return game_info

def get_xciheader(oflist,osizelist,sec_hashlist):
	upd_list=list()
	norm_list=list()
	sec_list=oflist
	sec_fileSizes = osizelist
	sec_shalist = sec_hashlist

	root_header,upd_header,norm_header,sec_header,rootSize,upd_multiplier,norm_multiplier,sec_multiplier=gen_rhfs0_head(upd_list,norm_list,sec_list,sec_fileSizes,sec_shalist)
	tot_size=0xF000+rootSize

	signature=randhex(0x100)
	signature= bytes.fromhex(signature)

	sec_offset=root_header[0x90:0x90+0x8]
	sec_offset=int.from_bytes(sec_offset, byteorder='little')
	sec_offset=int((sec_offset+0xF000+0x200)/0x200)
	sec_offset=sec_offset.to_bytes(4, byteorder='little')
	back_offset=(0xFFFFFFFF).to_bytes(4, byteorder='little')
	kek=(0x00).to_bytes(1, byteorder='big')
	cardsize,access_freq=getGCsize(tot_size)
	cardsize=cardsize.to_bytes(1, byteorder='big')
	GC_ver=(0x00).to_bytes(1, byteorder='big')
	GC_flag=(0x00).to_bytes(1, byteorder='big')
	pack_id=(0x8750F4C0A9C5A966).to_bytes(8, byteorder='big')
	valid_data=int(((tot_size-0x1)/0x200))
	valid_data=valid_data.to_bytes(8, byteorder='little')

	try:
		get('xci_header_key')
		key= get('xci_header_key')
		key= bytes.fromhex(key)
		IV=randhex(0x10)
		IV= bytes.fromhex(IV)
		xkey=True

	except:
		IV=(0x5B408B145E277E81E5BF677C94888D7B).to_bytes(16, byteorder='big')
		xkey=False


	HFS0_offset=(0xF000).to_bytes(8, byteorder='little')
	len_rHFS0=(len(root_header)).to_bytes(8, byteorder='little')
	sha_rheader=sha256(root_header[0x00:0x200]).hexdigest()
	sha_rheader=bytes.fromhex(sha_rheader)
	sha_ini_data=bytes.fromhex('1AB7C7B263E74E44CD3C68E40F7EF4A4D6571551D043FCA8ECF5C489F2C66E7E')
	SM_flag=(0x01).to_bytes(4, byteorder='little')
	TK_flag=(0x02).to_bytes(4, byteorder='little')
	K_flag=(0x0).to_bytes(4, byteorder='little')
	end_norm = sec_offset

	header =  b''
	header += signature
	header += b'HEAD'
	header += sec_offset
	header += back_offset
	header += kek
	header += cardsize
	header += GC_ver
	header += GC_flag
	header += pack_id
	header += valid_data
	header += IV
	header += HFS0_offset
	header += len_rHFS0
	header += sha_rheader
	header += sha_ini_data
	header += SM_flag
	header += TK_flag
	header += K_flag
	header += end_norm

	if xkey==True:
		firm_ver='0100000000000000'
		access_freq=access_freq
		Read_Wait_Time='88130000'
		Read_Wait_Time2='00000000'
		Write_Wait_Time='00000000'
		Write_Wait_Time2='00000000'
		Firmware_Mode='00110C00'
		CUP_Version='5a000200'
		Empty1='00000000'
		Upd_Hash='9bfb03ddbb7c5fca'
		CUP_Id='1608000000000001'
		Empty2='00'*0x38
		#print(hx(Empty2))

		firm_ver=bytes.fromhex(firm_ver)
		access_freq=bytes.fromhex(access_freq)
		Read_Wait_Time=bytes.fromhex(Read_Wait_Time)
		Read_Wait_Time2=bytes.fromhex(Read_Wait_Time2)
		Write_Wait_Time=bytes.fromhex(Write_Wait_Time)
		Write_Wait_Time2=bytes.fromhex(Write_Wait_Time2)
		Firmware_Mode=bytes.fromhex(Firmware_Mode)
		CUP_Version=bytes.fromhex(CUP_Version)
		Empty1=bytes.fromhex(Empty1)
		Upd_Hash=bytes.fromhex(Upd_Hash)
		CUP_Id=bytes.fromhex(CUP_Id)
		Empty2=bytes.fromhex(Empty2)

		Game_info =  b''
		Game_info += firm_ver
		Game_info += access_freq
		Game_info += Read_Wait_Time
		Game_info += Read_Wait_Time2
		Game_info += Write_Wait_Time
		Game_info += Write_Wait_Time2
		Game_info += Firmware_Mode
		Game_info += CUP_Version
		Game_info += Empty1
		Game_info += Upd_Hash
		Game_info += CUP_Id
		Game_info += Empty2

		gamecardInfoIV=IV[::-1]
		crypto = AES.new(key, AES.MODE_CBC, gamecardInfoIV)
		enc_info=crypto.encrypt(Game_info)
	if xkey==False:
		enc_info=get_enc_gameinfo(tot_size)

	sig_padding='00'*0x6E00
	sig_padding=bytes.fromhex(sig_padding)

	fake_CERT='FF'*0x8000
	fake_CERT=bytes.fromhex(fake_CERT)

	return header,enc_info,sig_padding,fake_CERT,root_header,upd_header,norm_header,sec_header,rootSize,upd_multiplier,norm_multiplier,sec_multiplier


keys = {}
titleKeks = []
keyAreaKeys = []

def set_dev_environment():
	global key_system
	key_system="development"
def set_prod_environment():	
	global key_system
	key_system="production"

try:
	a=key_system
except:
	set_prod_environment()	

def getMasterKeyIndex(i):
	if i > 0:
		return i-1
	else:
		return 0

def keyAreaKey(cryptoType, i):
	return keyAreaKeys[cryptoType][i]

def get(key):
	return keys[key]
	
def getTitleKek(i):
	return titleKeks[i]
	
def decryptTitleKey(key, i):
	kek = getTitleKek(i)
	
	crypto = AES.new(uhx(kek), AES.MODE_ECB)
	return crypto.decrypt(key)
	
def encryptTitleKey(key, i):
	kek = getTitleKek(i)
	
	crypto = AES.new(uhx(kek), AES.MODE_ECB)
	return crypto.encrypt(key)
	
def changeTitleKeyMasterKey(key, currentMasterKeyIndex, newMasterKeyIndex):
	return encryptTitleKey(decryptTitleKey(key, currentMasterKeyIndex), newMasterKeyIndex)

def generateKek(src, masterKey, kek_seed, key_seed):
	kek = []
	src_kek = []

	crypto = AES.new(masterKey, AES.MODE_ECB)
	kek = crypto.decrypt(kek_seed)

	crypto = AES.new(kek, AES.MODE_ECB)
	src_kek = crypto.decrypt(src)

	if key_seed != None:
		crypto = AES.new(src_kek, AES.MODE_ECB)
		return crypto.decrypt(key_seed)
	else:
		return src_kek
		
def unwrapAesWrappedTitlekey(wrappedKey, keyGeneration):
	aes_kek_generation_source = uhx(keys['aes_kek_generation_source'])
	aes_key_generation_source = uhx(keys['aes_key_generation_source'])
	
	if keyGeneration<10:
		mk = 'master_key_0'
	else:
		mk = 'master_key_'	

	kek = generateKek(uhx(keys['key_area_key_application_source']), uhx(keys[mk + str(keyGeneration)]), aes_kek_generation_source, aes_key_generation_source)

	crypto = AES.new(kek, AES.MODE_ECB)
	return crypto.decrypt(wrappedKey)		
	
def getKey(key):
	if key not in keys:
		raise IOError('%s missing from keys.txt' % key)
	return uhx(keys[key])

def masterKey(masterKeyIndex):
	return getKey('master_key_0' + str(masterKeyIndex))

def load(fileName):
	global keyAreaKeys
	global titleKeks

	with open(fileName, encoding="utf8") as f:
		for line in f.readlines():
			r = re.match(r'\s*([a-z0-9_]+)\s*=\s*([A-F0-9]+)\s*', line, re.I)
			if r:
				keyname=r.group(1)
				if keyname.startswith('master_key_'):
					if keyname[-2]!='0':
						num=keyname[-2:]
					else:	
						num=keyname[-1]
					try:	
						num=int(int(num,16))
					except:
						num=int(num,10)
					if len(str(num))<2:
						num='0'+str(num)
					keyname='master_key_'+str(num)	
				keys[keyname] = r.group(2)				
		if 'master_key_16' in keys.keys() and not 'master_key_10' in keys.keys() and not 'master_key_11' in keys.keys() and not 'master_key_12' in keys.keys() and not 'master_key_13' in keys.keys() and not 'master_key_14' in keys.keys() and not 'master_key_15' in keys.keys():
			keys['master_key_10'] = keys['master_key_16']
			del keys['master_key_16']
	
	aes_kek_generation_source = uhx(keys['aes_kek_generation_source'])
	aes_key_generation_source = uhx(keys['aes_key_generation_source'])

	keyAreaKeys = []
	for i in range(20):
		keyAreaKeys.append([None, None, None])

	for i in range(20):
		if i<10:
			masterKeyName = 'master_key_0' + str(i)
		else:
			masterKeyName = 'master_key_' + str(i)			
		if masterKeyName in keys.keys():
			masterKey = uhx(keys[masterKeyName])
			crypto = AES.new(masterKey, AES.MODE_ECB)
			titleKeks.append(crypto.decrypt(uhx(keys['titlekek_source'])).hex())
			keyAreaKeys[i][0] = generateKek(uhx(keys['key_area_key_application_source']), masterKey, aes_kek_generation_source, aes_key_generation_source)
			keyAreaKeys[i][1] = generateKek(uhx(keys['key_area_key_ocean_source']), masterKey, aes_kek_generation_source, aes_key_generation_source)
			keyAreaKeys[i][2] = generateKek(uhx(keys['key_area_key_system_source']), masterKey, aes_kek_generation_source, aes_key_generation_source)
		else:
			pass

if key_system =="production":
	raw_keys_file = Path('keys.txt')
	raw_keys_file2 = Path('ztools\\keys.txt')
	raw_keys_file3 = Path('ztools/keys.txt')
else:
	raw_keys_file = Path('dev_keys.txt')
	raw_keys_file2 = Path('ztools\\dev_keys.txt')
	raw_keys_file3 = Path('ztools/keys.txt')	
	
if raw_keys_file.is_file():
	load(raw_keys_file)
elif raw_keys_file2.is_file():
	load(raw_keys_file2)
elif raw_keys_file3.is_file():
	load(raw_keys_file3)	
	
if not raw_keys_file.is_file() and not raw_keys_file2.is_file() and not raw_keys_file3.is_file():
	print('keys.txt missing')

def gen_rhfs0_head(upd_list, norm_list, sec_list, sec_file_sizes, sec_shalist):
    """Generate root HFS0 header structure"""
    # Generate individual headers
    upd_header, upd_size, upd_multiplier = _gen_hfs0_header(upd_list, [], [])
    norm_header, norm_size, norm_multiplier = _gen_hfs0_header(norm_list, [], [])
    sec_header, sec_size, sec_multiplier = _gen_hfs0_header(sec_list, sec_file_sizes, sec_shalist)
    
    # Generate root header
    root_hreg = [
        (0x200 * upd_multiplier).to_bytes(4, byteorder='little'),
        (0x200 * norm_multiplier).to_bytes(4, byteorder='little'),
        (0x200 * sec_multiplier).to_bytes(4, byteorder='little')
    ]
    
    root_list = ["update", "normal", "secure"]
    root_file_sizes = [upd_size, norm_size, sec_size]
    root_shalist = [
        sha256(upd_header).hexdigest(),
        sha256(norm_header).hexdigest(),
        sha256(sec_header).hexdigest()
    ]
    
    root_header, root_size, root_multiplier = _gen_hfs0_header(
        root_list, root_file_sizes, root_shalist, root_hreg
    )
    
    return root_header, upd_header, norm_header, sec_header, root_size, upd_multiplier, norm_multiplier, sec_multiplier

def _gen_hfs0_header(file_list, file_sizes=None, sha_list=None, hash_regions=None):
    """Generate HFS0 header for given file list"""
    files_nb = len(file_list)
    string_table = '\x00'.join(str(nca) for nca in file_list)
    header_size = 0x10 + files_nb * HFS0_ENTRY_SIZE + len(string_table)
    multiplier = math.ceil(header_size / 0x200)
    remainder = 0x200 * multiplier - header_size
    header_size += remainder
    
    # Use provided file sizes or empty list
    if file_sizes is None:
        file_sizes = [0] * files_nb
    
    # Calculate file offsets
    file_offsets = [sum(file_sizes[:n]) for n in range(files_nb)]
    
    # Use provided SHA list or empty hashes
    if sha_list is None:
        sha_list = ['00' * 32] * files_nb
    
    # Calculate string table offsets
    file_names_lengths = [len(os.path.basename(str(file))) + 1 for file in file_list]
    string_table_offsets = [sum(file_names_lengths[:n]) for n in range(files_nb)]
    
    # Default hash region
    default_hash_region = (0x200).to_bytes(4, byteorder='little')
    
    # Build header
    header = b'HFS0'
    header += pk('<I', files_nb)
    header += pk('<I', len(string_table) + remainder)
    header += b'\x00\x00\x00\x00'
    
    for n in range(files_nb):
        header += pk('<Q', file_offsets[n])
        header += pk('<Q', file_sizes[n])
        header += pk('<I', string_table_offsets[n])
        
        # Use custom hash region if provided, otherwise default
        if hash_regions and n < len(hash_regions):
            header += hash_regions[n]
        else:
            header += default_hash_region
            
        header += b'\x00\x00\x00\x00\x00\x00\x00\x00'
        header += bytes.fromhex(sha_list[n])
    
    header += string_table.encode()
    header += remainder * b'\x00'
    
    total_size = len(header) + sum(file_sizes)
    return header, total_size, multiplier



if __name__ == '__main__':
    sys.exit(main())