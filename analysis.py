import pytsk3
import os
import sys
import hashlib
from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
# CORRECTED IMPORT: Using the ShimcachePlugin (shimcache.py) which is confirmed to be installed.
from regipy.plugins.system.shimcache import ShimCachePlugin
# You could also use usbstor.py for USB device history if needed:
# from regipy.plugins.system.usbstor import UsbstorPlugin


# Define constants for file types (TSK standard)
TSK_FS_TYPE_ENUM = {
    pytsk3.TSK_FS_META_TYPE_UNDEF: "Unknown",
    pytsk3.TSK_FS_META_TYPE_REG: "File", 
    pytsk3.TSK_FS_META_TYPE_DIR: "Directory",
    pytsk3.TSK_FS_META_TYPE_LNK: "Link",
    pytsk3.TSK_FS_META_TYPE_FIFO: "Pipe",
    pytsk3.TSK_FS_META_TYPE_CHR: "Character Device",
    pytsk3.TSK_FS_META_TYPE_BLK: "Block Device"
}

# --- New Carving Signatures (Header/Footer based) ---
FILE_SIGNATURES = {
    "JPEG": {
        "header": b'\xFF\xD8\xFF\xE0',
        "footer": b'\xFF\xD9',
        "ext": "jpg"
    },
    "PDF": {
        "header": b'\x25\x50\x44\x46', # %PDF
        "footer": b'\x25\x25\x45\x4F\x46', # %%EOF
        "ext": "pdf"
    },
    "GIF": {
        "header": b'\x47\x49\x46\x38\x39\x61', # GIF89a
        "footer": b'\x00\x3B', # Null byte and semicolon
        "ext": "gif"
    }
}

# --- File System Traversal Function ---
def traverse_directory(directory, fs, depth):
    """Recursively traverses directories to list files and folders."""
    
    indent = "  " * depth
    
    for entry in directory:
        if entry.info.name.name in [b".", b".."]:
            continue

        try:
            file_name = entry.info.name.name.decode('utf-8')
        except UnicodeDecodeError:
            file_name = entry.info.name.name.decode('latin-1') 
        
        if entry.info.meta:
            meta_type = entry.info.meta.type
            file_type = TSK_FS_TYPE_ENUM.get(meta_type, "Unknown")
            
            inode = entry.info.meta.addr
            size = entry.info.meta.size
            m_time = entry.info.meta.mtime
            
            print(f"{indent}|-- [{file_type:<10}] {file_name:<40} (i-node: {inode} | Size: {size} bytes | MTime: {m_time})")

            if meta_type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    subdir = fs.open_dir(inode=inode)
                    traverse_directory(subdir, fs, depth + 1)
                except Exception as e:
                    print(f"{indent}|-- ERROR: Cannot open subdirectory for i-node {inode}: {e}")

# --- File System Analysis Function ---
def analyze_disk_image(image_path):
    """Opens a disk image and attempts to open the file system directly (no partition table)."""
    print(f"\n[+] Starting File System Analysis on: {image_path}")
    
    try:
        img = pytsk3.Img_Info(image_path)
        print("\n[--- DIRECT FILE SYSTEM ANALYSIS (Attempting at Offset 0) ---]")
        
        try:
            fs = pytsk3.FS_Info(img, offset=0) 
            print(f"| Status: SUCCESS | FS Type: {fs.info.ftype} | Block Size: {fs.info.block_size}")
            
            print("\n[--- ACTIVE FILE LISTING ---]")
            root_dir = fs.open_dir(path="/")
            traverse_directory(root_dir, fs, depth=0)
            
        except IOError as e:
            print(f"| Status: FAILED (No recognized File System at offset 0). Error: {e}")

    except IOError as e:
        print(f"\nCRITICAL ERROR: Failed to open image file: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred during analysis: {e}")

# --- File Carving Function ---
def perform_file_carving(image_path, output_directory, signatures=FILE_SIGNATURES):
    """Scans the raw image data for file signatures and carves out the data."""
    # ... (function body remains the same) ...
    print(f"\n[+] Starting File Carving on raw data of: {image_path}")
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
        
    carved_count = 0

    try:
        with open(image_path, 'rb') as f:
            buffer = f.read()

            for file_type, sigs in signatures.items():
                header = sigs['header']
                footer = sigs['footer']
                ext = sigs['ext']
                
                print(f"  Searching for {file_type} (.{ext}) header: {header.hex()}...")
                
                offset = 0
                while True:
                    header_pos = buffer.find(header, offset)
                    if header_pos == -1:
                        break # No more headers found
                    
                    footer_pos = buffer.find(footer, header_pos + len(header))
                    
                    if footer_pos != -1:
                        carved_data = buffer[header_pos : footer_pos + len(footer)]
                        
                        output_filename = os.path.join(output_directory, f"carved_{file_type}_{carved_count}.{ext}")
                        with open(output_filename, 'wb') as out_f:
                            out_f.write(carved_data)
                            
                        print(f"    - Carved {file_type} file of size {len(carved_data)} bytes at offset {header_pos}")
                        carved_count += 1
                        
                        offset = footer_pos + len(footer)
                    else:
                        offset = header_pos + len(header)

            print(f"\n[+] Carving Complete. Total files recovered: {carved_count}")

    except Exception as e:
        print(f"An error occurred during carving: {e}")

# --- New Registry Analysis Function (MODIFIED FOR SHIMCACHE) ---
def analyze_registry_hive(hive_path, registry_name):
    """
    Loads a Windows Registry hive and runs forensic plugins to extract artifacts.
    Now uses the ShimcachePlugin for Program Execution Analysis.
    """
    print(f"\n[+] Starting Registry Analysis on: {registry_name} Hive ({hive_path})")
    
    if not os.path.exists(hive_path):
        print(f"ERROR: Registry hive file not found at {hive_path}. Cannot proceed.")
        return

    try:
        # Load the Registry Hive object
        registry_hive = RegistryHive(hive_path)
        
        # --- MODIFIED: Running the ShimcachePlugin (a crucial artifact) ---
        print("--- EXTRACTING PROGRAM EXECUTION ARTIFACTS (Shimcache/P2) ---")
        
        shimcache_plugin = ShimcachePlugin(registry_hive, as_json=True)
        shimcache_plugin.run()
        
        results = shimcache_plugin.entries
        
        if results:
            print(f"Found {len(results)} Shimcache entries (recently executed programs):")
            # Print the first few results
            for i, entry in enumerate(results):
                # Shimcache entries contain 'path', 'mtime' (last modification time) and 'lntime' (last execution time)
                print(f"  [{i+1}] Executable: {entry.get('path')}")
                print(f"      Last Modified Time: {entry.get('mtime')}")
                if i >= 4: # Limit output for console view
                    print("  ... and more (full data available in JSON output)")
                    break
        else:
            print("No Shimcache entries extracted.")

        # Optional: Run all relevant plugins 
        # print("\n--- RUNNING ALL RELEVANT PLUGINS (Requires regipy[full] installation) ---")
        # all_plugin_results = run_relevant_plugins(registry_hive, as_json=True)
        # print(f"Total plugins executed: {len(all_plugin_results)}")

    except Exception as e:
        print(f"An error occurred during Registry Analysis: {e}")


# --- Example Execution (Updated Main Block) ---
if __name__ == '__main__':
    # --- DISK IMAGE VARIABLES ---
    IMAGE_TO_ANALYZE = "test_image.dd" 
    CARVED_OUTPUT_DIR = "carved_files_output"
    
    # --- REGISTRY TESTING VARIABLES ---
    # Shimcache is typically found in the SYSTEM hive, so we change the test name for accuracy.
    MOCK_REGISTRY_HIVE = "SYSTEM_TEST_HIVE.DAT" 

    # --- MOCK SETUP: Create a dummy file to avoid errors if the hive is missing ---
    if not os.path.exists(MOCK_REGISTRY_HIVE):
        print(f"\n[!] Place a real Windows 'SYSTEM' hive file here, naming it: {MOCK_REGISTRY_HIVE}")
        try:
            with open(MOCK_REGISTRY_HIVE, 'w') as f:
                f.write("")
        except Exception:
            pass # Ignore if creation fails

    # --- EXECUTION ---
    print("\n========================================================")
    print("           DIGITAL FORENSICS SUITE - ANALYSIS")
    print("========================================================\n")
    
    # 1. Run File System Analysis (Disk Content Listing)
    if os.path.exists(IMAGE_TO_ANALYZE):
        analyze_disk_image(IMAGE_TO_ANALYZE)
    
    # 2. Run File Carving (Deleted Data Recovery)
    perform_file_carving(IMAGE_TO_ANALYZE, CARVED_OUTPUT_DIR)

    # 3. Run Registry Analysis (The main focus of this task)
    analyze_registry_hive(MOCK_REGISTRY_HIVE, "SYSTEM")
    
    print("\n========================================================\n")