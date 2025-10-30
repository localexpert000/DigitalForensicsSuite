import pytsk3
import os
import sys

# Define constants for file types (TSK standard)
TSK_FS_TYPE_ENUM = {
    pytsk3.TSK_FS_META_TYPE_UNDEF: "Unknown",
    pytsk3.TSK_FS_META_TYPE_FILE: "File",
    pytsk3.TSK_FS_META_TYPE_DIR: "Directory",
    pytsk3.TSK_FS_META_TYPE_LINK: "Link",
    pytsk3.TSK_FS_META_TYPE_FIFO: "Pipe",
    pytsk3.TSK_FS_META_TYPE_CHR: "Character Device",
    pytsk3.TSK_FS_META_TYPE_BLK: "Block Device"
}

def analyze_disk_image(image_path):
    """
    Opens a disk image, lists partitions, and attempts to open the file system.
    """
    print(f"\n[+] Starting File System Analysis on: {image_path}")
    
    try:
        # Step 1: Get the Image Handle (Img_Info)
        # This object provides raw read access to the image file.
        img = pytsk3.Img_Info(image_path)
        
        # Step 2: Get Volume/Partition Info (Volume_Info)
        # This reads the partition table (MBR/GPT) from the image.
        vol = pytsk3.Volume_Info(img)

        # Iterate over all detected partitions
        print("\n[--- PARTITIONS FOUND ---]")
        for part in vol:
            if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                # Only analyze allocated (active) partitions
                print(f"| ID: {part.addr:<3} | Type: {part.desc:<30} | Start Offset: {part.start * img.info.dev_size // vol.info.block_size} bytes")
                
                # Step 3: Attempt to Open the File System (FS_Info)
                # The offset is the starting position of the partition in the image (in bytes).
                try:
                    fs = pytsk3.FS_Info(img, offset=part.start * vol.info.block_size)
                    print(f"| Status: SUCCESS | FS Type: {fs.info.ftype} | Block Size: {fs.info.block_size}")
                    
                    # Call the recursive function to traverse and list files
                    print("\n[--- FILE LISTING ---]")
                    root_dir = fs.open_dir(path="/")
                    
                    # Start the recursive directory traversal from the root
                    traverse_directory(root_dir, fs, depth=0)
                    
                except IOError:
                    print(f"| Status: FAILED (No recognized File System at offset {part.start * vol.info.block_size})")

    except IOError as e:
        print(f"\nCRITICAL ERROR: Failed to open image or read volume structure: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred during analysis: {e}")

def traverse_directory(directory, fs, depth):
    """Recursively traverses directories to list files and folders."""
    
    indent = "  " * depth
    
    # Loop through all directory entries (files and subdirectories)
    for entry in directory:
        # TSK structures contain . and .. entries; skip them for cleaner output
        if entry.info.name.name in [".", ".."]:
            continue

        file_name = entry.info.name.name
        
        # Check if the TSK object contains metadata (meta)
        if entry.info.meta:
            meta_type = entry.info.meta.type
            file_type = TSK_FS_TYPE_ENUM.get(meta_type, "Unknown")
            
            # --- EXTRACT KEY METADATA ---
            # i-node/MFT entry number (crucial for forensic tracking)
            inode = entry.info.meta.addr
            
            # File size
            size = entry.info.meta.size

            # Last Modified Time (mtime)
            # TSK stores time as Unix epoch seconds; needs conversion for display
            m_time = entry.info.meta.mtime
            
            print(f"{indent}|-- [{file_type:<10}] {file_name:<40} (i-node: {inode} | Size: {size} bytes | MTime: {m_time})")

            # RECURSION: If the entry is a Directory, call this function again on the subdirectory
            if meta_type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    # Open the subdirectory object
                    subdir = fs.open_dir(inode=inode)
                    # Recursively call this function for the subdirectory
                    traverse_directory(subdir, fs, depth + 1)
                except Exception as e:
                    print(f"{indent}|-- ERROR: Cannot open subdirectory for i-node {inode}: {e}")

# --- Example Execution ---
if __name__ == '__main__':
    # NOTE: You MUST use an image file that contains a file system (like the one 
    # created by a tool like FTK Imager, or a simple .dd image of a partition).
    # The 'forensic_image.dd' created in Task 7 of this guide is a raw byte stream, 
    # but TSK needs a recognized partition table and file system inside.
    
    # For a successful PyTSK3 test, use a known good raw disk image of a partition (e.g., a simple Linux partition DD image)
    
    IMAGE_TO_ANALYZE = "forensic_image.dd" 
    
    if not os.path.exists(IMAGE_TO_ANALYZE):
        print(f"FATAL: Image file '{IMAGE_TO_ANALYZE}' not found. Please run acquisition_tool.py or replace with a test image.")
    else:
        analyze_disk_image(IMAGE_TO_ANALYZE)