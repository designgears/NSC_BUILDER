#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import tempfile
import struct

# Import required ztools modules
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'py', 'ztools'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'py', 'ztools', 'lib'))

import decompressor
import sq_tools

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
                
                self.files.append({
                    'name': name.decode('utf-8'),
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
            title_id = struct.unpack('<Q', cnmt_data[0x00:0x08])[0]
            title_version = struct.unpack('<I', cnmt_data[0x08:0x0C])[0]
            content_meta_type = cnmt_data[0x0C]
            content_count = struct.unpack('<H', cnmt_data[0x0E:0x10])[0]
            meta_count = struct.unpack('<H', cnmt_data[0x10:0x12])[0]
            
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
                content_hash = cnmt_data[entry_offset:entry_offset + 0x20]  # 32 bytes hash
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
    """Decompress NSZ to NSP using ztools decompressor"""
    try:
        decompressor.decompress_nsz(input_path, output_path, buffer_size)
        return True
    except Exception as e:
        print(f"Error decompressing NSZ {input_path}: {e}")
        return False

def decompress_xcz(input_path, output_path, buffer_size=65536):
    """Decompress XCZ to XCI using ztools decompressor"""
    try:
        decompressor.decompress_xcz(input_path, output_path, buffer_size)
        return True
    except Exception as e:
        print(f"Error decompressing XCZ {input_path}: {e}")
        return False



def copy_file_content(src_path, dst_file, offset, size, buffer_size=65536):
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

def main():
    parser = argparse.ArgumentParser(description='Standalone Squirrel - NSP/XCI repackaging and NSZ/XCZ decompression')
    
    # Core arguments
    parser.add_argument('file', nargs='*', help='Input files')
    parser.add_argument('-dc', '--direct_creation', nargs='+', help='Create directly a nsp or xci')
    parser.add_argument('-dmul', '--direct_multi', nargs='+', help='Create directly a multi nsp or xci')
    parser.add_argument('-dcpr', '--decompress', help='Decompress a nsz, xcz or ncz')
    
    # Options
    parser.add_argument('-o', '--ofolder', nargs='+', help='Set output folder')
    parser.add_argument('-tfile', '--text_file', help='Input text file with file list')
    parser.add_argument('-b', '--buffer', type=int, default=65536, help='Set buffer size')
    parser.add_argument('-t', '--type', default='xci', help='Set output type (xci only - NSP/NSZ inputs convert to XCI)')
    parser.add_argument('-fat', '--fat', default='exfat', help='Set FAT format (fat32, exfat)')
    parser.add_argument('-fx', '--fexport', default='files', help='Export format (files, folder)')
    parser.add_argument('-ND', '--nodelta', action='store_true', default=True, help='Disable delta fragments')
    parser.add_argument('-pv', '--patchversion', default='0', help='Patch version')
    parser.add_argument('-kp', '--keypatch', default='False', help='Key patch')
    parser.add_argument('-rsvc', '--RSVcap', type=int, default=268435656, help='RSV capacity')
    parser.add_argument('-roma', '--romanize', action='store_true', default=True, help='Romanize names')
    parser.add_argument('-rn', '--rename', help='Rename output file')
    
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
            
    except Exception:
        return 1

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
        # NCZ decompression would need more complex implementation
        temp_file = os.path.join(temp_dir, basename[:-1] + 'a')  # .ncz -> .nca
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
        return 1
    else:
        raise ValueError(f"Unsupported file type: {filepath}")
    
    return 0 if success else 1

def handle_direct_creation(args):
    """Handle NSP/XCI direct creation (repackaging)"""
    return 1

def handle_direct_multi(args):
    """Handle direct multi creation (-dmul)"""
    if len(args.direct_multi) < 2:
        return 1
    
    action, export_type = args.direct_multi[0], args.direct_multi[1]
    
    if export_type.lower() != 'xci':
        return 1
    
    if not args.text_file:
        return 1
    
    # Get file list
    file_list = get_file_list(args.text_file)
    if not file_list:
        return 1
    
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
        
        # Generate proper file hashes for secure partition (matching original NSC_Builder approach)
        # Original NSC_Builder uses dummy hashes for performance - we'll do the same
        sec_hashlist = []
        for filename in all_files:
            # Use dummy hash like original NSC_Builder (Fs/Xci.py line 17)
            sha = '0000000000000000000000000000000000000000000000000000000000000000'
            sec_hashlist.append(sha)

        # Use ztools sq_tools.get_xciheader function for XCI header generation
        xci_header, game_info, sig_padding, xci_certificate, root_header, upd_header, norm_header, sec_header, rootSize, upd_multiplier, norm_multiplier, sec_multiplier = sq_tools.get_xciheader(all_files, all_sizes, sec_hashlist)
        
        # Calculate total size like original
        tot_size = 0xF000 + rootSize
        with open(outfile, 'wb') as xci_file:
            # Write complete XCI header structure (same as working XCI creation)
            xci_file.write(xci_header)
            xci_file.write(game_info)
            xci_file.write(sig_padding)
            xci_file.write(xci_certificate)
            xci_file.write(root_header)  # Root HFS0 header
            xci_file.write(upd_header)  # Update partition (empty)
            xci_file.write(norm_header)  # Normal partition (empty)
            xci_file.write(sec_header)  # Secure partition header
            
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
        
        # Cleanup temp files
        if temp_files:
            cleanup_temp_files(temp_files)
        
        return True
        
    except Exception:
        # Ensure temp files are cleaned up even on error
        if 'temp_files' in locals() and temp_files:
            cleanup_temp_files(temp_files)
        return False

if __name__ == '__main__':
    sys.exit(main())