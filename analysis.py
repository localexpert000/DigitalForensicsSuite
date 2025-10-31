import pytsk3
import os
import sys
import hashlib
import subprocess 
from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
from regipy.plugins.system.shimcache import ShimCachePlugin 

# --- REPORTLAB IMPORTS (NEW for Phase 4) ---
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
import pandas as pd # Although pandas is imported, it's not strictly used in the current report logic

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

# --- File Signatures ---
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
            # NOTE: Returning carved_count for the report generator (NEW)
            return carved_count

    except Exception as e:
        print(f"An error occurred during carving: {e}")
        return 0

# --- Registry Analysis Function ---
def analyze_registry_hive(hive_path, registry_name):
    """Loads a Windows Registry hive and runs forensic plugins to extract artifacts."""
    print(f"\n[+] Starting Registry Analysis on: {registry_name} Hive ({hive_path})")
    
    if not os.path.exists(hive_path):
        print(f"ERROR: Registry hive file not found at {hive_path}. Cannot proceed.")
        return "ERROR: Hive file not found."

    try:
        registry_hive = RegistryHive(hive_path)
        print("--- EXTRACTING PROGRAM EXECUTION ARTIFACTS (Shimcache/P2) ---")
        shimcache_plugin = ShimCachePlugin(registry_hive, as_json=True)
        shimcache_plugin.run()
        results = shimcache_plugin.entries
        
        summary = f"Found {len(results)} Shimcache entries." if results else "No Shimcache entries extracted."

        if results:
            print(f"Found {len(results)} Shimcache entries (recently executed programs):")
            for i, entry in enumerate(results):
                print(f"  [{i+1}] Executable: {entry.get('path')}")
                if i >= 4: break

        # Returning a simplified string summary for the report (NEW)
        return summary

    except Exception as e:
        print(f"An error occurred during Registry Analysis: {e}")
        return f"ERROR: Registry Analysis failed: {e}"


# --- New Memory Analysis Function (P2 Features) ---
def analyze_memory_dump(memory_dump_path):
    """
    Analyzes a memory dump using the Volatility3 framework via subprocess.
    """
    print(f"\n[+] Starting Memory Analysis on: {memory_dump_path}")
    
    if not os.path.exists(memory_dump_path):
        print(f"ERROR: Memory dump file not found at {memory_dump_path}")
        return "ERROR: Memory dump file not found."

    process_list_command = ['vol.py', '-f', memory_dump_path, 'windows.pslist.PsList']
    
    # --- EXECUTE PSLIST (Process Analysis) ---
    print("\n--- Running windows.pslist.PsList (Processes) ---")
    try:
        process_result = subprocess.run(process_list_command, 
                                        capture_output=True, text=True, check=True)
        print(process_result.stdout)
        summary = f"Process listing successful. Found {process_result.stdout.count('Offset') - 1} processes."
        return summary
    except Exception as e:
        print(f"ERROR: Volatility PsList failed. Error: {e}")
        return f"ERROR: Volatility Analysis failed: {e}"


# --- New Reporting Function (P4 Feature) ---
def generate_forensic_report(case_name, report_data):
    """
    Generates a formal, multi-section forensic report in PDF format.
    report_data is a dictionary containing structured data from analysis.
    """
    report_filename = f"{case_name}_Forensic_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(report_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    Story = []

    # --- 1. Header and Chain of Custody ---
    Story.append(Paragraph(f"<u>Forensic Examination Report: {case_name}</u>", styles['h1']))
    Story.append(Paragraph(f"**Date Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    Story.append(Paragraph(f"**Investigator:** Digital Forensics Suite (S24BINCE1M04006, S24BINCE1M04018, S24BINCE1M04020)", styles['Normal']))
    Story.append(Spacer(1, 0.2 * 72))

    # --- Chain of Custody Log ---
    custody_data = [
        ['Date/Time', 'Action', 'Evidence Hash (SHA-256)', 'Examiner'],
        [report_data.get('AcquisitionTime', 'N/A'), 'Acquisition Started', report_data.get('SourceHash', 'N/A'), 'Automated Tool'],
        [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Analysis Completed', 'N/A', 'Suite User']
    ]
    custody_table = Table(custody_data)
    custody_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    Story.append(Paragraph("<b>Chain of Custody and Integrity Log:</b>", styles['h3']))
    Story.append(custody_table)
    Story.append(Spacer(1, 0.4 * 72))
    
    # --- 2. Key Findings ---
    Story.append(Paragraph("<u>Key Findings Summary</u>", styles['h2']))
    
    # Add Registry Analysis Summary
    reg_summary = report_data.get('RegistrySummary', 'No Registry Analysis performed.')
    Story.append(Paragraph(f"<b>Registry Artifacts (Shimcache):</b> {reg_summary}", styles['Normal']))
    
    # Add File Carving Summary
    carving_count = report_data.get('CarvedCount', 0)
    Story.append(Paragraph(f"<b>File Carving:</b> {carving_count} deleted files recovered from unallocated space.", styles['Normal']))
    
    # Add Memory Analysis Summary
    mem_summary = report_data.get('MemorySummary', 'No Memory Analysis performed.')
    Story.append(Paragraph(f"<b>Memory (RAM) Analysis:</b> {mem_summary}", styles['Normal']))
    
    # --- 3. Build the PDF ---
    doc.build(Story)
    print(f"\n✅ REPORT GENERATED: Report saved as {report_filename}")
    return report_filename

# --- Example Execution (Updated Main Block) ---
if __name__ == '__main__':
    # --- DISK IMAGE VARIABLES ---
    IMAGE_TO_ANALYZE = "test_image.dd" 
    CARVED_OUTPUT_DIR = "carved_files_output"
    
    # --- TESTING VARIABLES ---
    MOCK_REGISTRY_HIVE = "SYSTEM_TEST_HIVE.DAT" 
    MOCK_MEMORY_DUMP = "memory.dmp" 

    # --- MOCK SETUP: Create dummy files if missing ---
    if not os.path.exists(MOCK_REGISTRY_HIVE):
        print(f"\n[!] Place a real Windows 'SYSTEM' hive file here, naming it: {MOCK_REGISTRY_HIVE}")
        try:
            with open(MOCK_REGISTRY_HIVE, 'w') as f: f.write("")
        except Exception: pass
        
    if not os.path.exists(MOCK_MEMORY_DUMP):
        print(f"\n[!] Place a real memory dump file (e.g., acquired via DumpIt) here, naming it: {MOCK_MEMORY_DUMP}")
        try:
            with open(MOCK_MEMORY_DUMP, 'w') as f: f.write("")
        except Exception: pass

    # --- EXECUTION ---
    print("\n========================================================")
    print("      DIGITAL FORENSICS SUITE - FULL ANALYSIS")
    print("========================================================\n")
    
    # --- 1. RUN ANALYSIS FUNCTIONS AND COLLECT RESULTS ---
    
    # Use a dummy hash/time since acquisition isn't run here
    REPORT_DATA = {
        'CaseID': 'TEST-P4-001',
        'SourceHash': '55a290c58509790860da55a47256188865bdd8dd5cbf7cd5c4b95cb5264f109a',
        'AcquisitionTime': '2025-10-31 10:00:00'
    }

    # 1a. File System Analysis (Run but output is only printed to console)
    if os.path.exists(IMAGE_TO_ANALYZE):
        analyze_disk_image(IMAGE_TO_ANALYZE)
    
    # 1b. File Carving
    carved_count = perform_file_carving(IMAGE_TO_ANALYZE, CARVED_OUTPUT_DIR)
    REPORT_DATA['CarvedCount'] = carved_count
    
    # 1c. Registry Analysis
    reg_summary = analyze_registry_hive(MOCK_REGISTRY_HIVE, "SYSTEM")
    REPORT_DATA['RegistrySummary'] = reg_summary

    # 1d. Memory Analysis
    mem_summary = analyze_memory_dump(MOCK_MEMORY_DUMP)
    REPORT_DATA['MemorySummary'] = mem_summary
    
    # --- 2. GENERATE REPORT ---
    generate_forensic_report(REPORT_DATA['CaseID'], REPORT_DATA)
    
    print("\n========================================================\n")