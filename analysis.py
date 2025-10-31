import pytsk3
import os
import sys

# Define constants for file types (TSK standard)
TSK_FS_TYPE_ENUM = {
    pytsk3.TSK_FS_META_TYPE_UNDEF: "Unknown",
    # Corrected constant for Regular File in this pytsk3 version
    pytsk3.TSK_FS_META_TYPE_REG: "File", 
    pytsk3.TSK_FS_META_TYPE_DIR: "Directory",
    # Corrected constant for Link in this pytsk3 version
    pytsk3.TSK_FS_META_TYPE_LNK: "Link",
    pytsk3.TSK_FS_META_TYPE_FIFO: "Pipe",
    pytsk3.TSK_FS_META_TYPE_CHR: "Character Device",
    pytsk3.TSK_FS_META_TYPE_BLK: "Block Device"
}

# --- New Carving Signatures (Header/Footer based) ---
# Hexadecimal byte patterns used for file carving
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

# --- File System Traversal Function (FINAL CORRECTED VERSION) ---
def traverse_directory(directory, fs, depth):
    """Recursively traverses directories to list files and folders."""
    
    # Using two spaces for indentation consistency
    indent = "  " * depth
    
    for entry in directory:
        # TSK structures contain . and .. entries; skip them for cleaner output
        if entry.info.name.name in [b".", b".."]: # Compare to bytes literal if needed
            continue

        # --- FIX: Decode file name inside the loop ---
        try:
            # Attempt to decode the name bytes (usually UTF-8)
            file_name = entry.info.name.name.decode('utf-8')
        except UnicodeDecodeError:
            # Fallback for corrupted or non-UTF-8 names
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

# --- File System Analysis Function (MODIFIED TO SUPPORT RAW FS IMAGE) ---
def analyze_disk_image(image_path):
    """
    Opens a disk image and attempts to open the file system directly (no partition table).
    """
    print(f"\n[+] Starting File System Analysis on: {image_path}")
    
    try:
        # Step 1: Get the Image Handle (Img_Info)
        img = pytsk3.Img_Info(image_path)
        
        print("\n[--- DIRECT FILE SYSTEM ANALYSIS (Attempting at Offset 0) ---]")
        
        # Step 2: Attempt to Open the File System (FS_Info) directly at offset 0
        try:
            fs = pytsk3.FS_Info(img, offset=0) 
            print(f"| Status: SUCCESS | FS Type: {fs.info.ftype} | Block Size: {fs.info.block_size}")
            
            # Call the recursive function to traverse and list files
            print("\n[--- ACTIVE FILE LISTING ---]")
            root_dir = fs.open_dir(path="/")
            
            # Start the recursive directory traversal from the root
            traverse_directory(root_dir, fs, depth=0)
            
        except IOError as e:
            print(f"| Status: FAILED (No recognized File System at offset 0). Error: {e}")

    except IOError as e:
        print(f"\nCRITICAL ERROR: Failed to open image file: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred during analysis: {e}")

# --- File Carving Function ---
def perform_file_carving(image_path, output_directory, signatures=FILE_SIGNATURES):
    """
    Scans the raw image data for file signatures and carves out the data.
    """
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


# --- Example Execution (Updated Main Block) ---
if __name__ == '__main__':
    # *** IMPORTANT: This is the name of the image you successfully created and populated. ***
    IMAGE_TO_ANALYZE = "test_image.dd" 
    CARVED_OUTPUT_DIR = "carved_files_output"

    if not os.path.exists(IMAGE_TO_ANALYZE):
        print(f"FATAL: Image file '{IMAGE_TO_ANALYZE}' not found. Please create a mock image with a file system first.")
    else:
        # 1. Run File System Analysis (Active files)
        analyze_disk_image(IMAGE_TO_ANALYZE)
        
        # 2. Run File Carving (Deleted/Fragmented data recovery)
        perform_file_carving(IMAGE_TO_ANALYZE, CARVED_OUTPUT_DIR)