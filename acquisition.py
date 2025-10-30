import subprocess
import hashlib
import os

# --- Configuration & Constants ---
HASH_ALGORITHM = 'sha256'
BLOCK_SIZE = 65536  # 64KB read/write buffer size for hashing and imaging (good performance balance)

# --- Hash Calculation Function ---
def calculate_hash_from_file(file_path, algorithm='sha256'):
    """Calculates the hash of a file or device in chunks for large data."""
    hash_obj = hashlib.new(algorithm)
    try:
        # Open in binary read mode 'rb'
        with open(file_path, 'rb') as f:
            while True:
                # Read data in fixed chunks
                data = f.read(BLOCK_SIZE)
                if not data:
                    break
                hash_obj.update(data)
        return hash_obj.hexdigest()
    except Exception as e:
        # Crucial for error logging in a forensic tool
        print(f"Error reading file/device for hashing: {e}")
        return None

# --- Forensic Imaging Function (Acquisition) ---
def perform_forensic_imaging(source_device, output_path, log_path):
    """
    Executes the disk imaging process using dcfldd (recommended) or dd.
    NOTE: Requires dcfldd to be installed on Linux/macOS, or equivalent access 
    to physical devices on Windows, and MUST be run with administrator/root privileges.
    """
    print(f"Starting imaging from {source_device} to {output_path}...")
    
    # Define the command list. We use dcfldd for its built-in hashing and progress status.
    command = [
        'dcfldd', 
        f'if={source_device}',      # Input File (the source device/file)
        f'of={output_path}',       # Output File (the resulting image file)
        f'bs={BLOCK_SIZE}',         # Block Size
        f'hash={HASH_ALGORITHM}',  # On-the-fly hash calculation (P1 feature)
        f'hashlog={log_path}',     # Log the hash value for chain of custody (P1 feature)
        'status=on'                 # Show real-time progress
    ]
    
    try:
        # Popen runs the command and allows us to read its output simultaneously
        process = subprocess.Popen(command, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   universal_newlines=True)

        # 1. LIVE PROGRESS MONITORING (for future PySide GUI integration)
        # We read the output to get the real-time status.
        for line in process.stderr:
            if 'copied' in line or 'STATUS:' in line:
                # In a full GUI, this line would update a QProgressBar
                print(f"STATUS: {line.strip()}") 
        
        # Wait for the command to finish
        process.wait()
        
        if process.returncode != 0:
            error_output = process.stderr.read()
            print(f"Imaging FAILED with error: {error_output}")
            return False, None
            
        print("\n--- Imaging Complete. Verification Check... ---")
        return True, log_path

    except FileNotFoundError:
        print("CRITICAL ERROR: 'dcfldd' command not found. Please install dcfldd or switch to standard 'dd' logic.")
        return False, None
    except Exception as e:
        print(f"An unexpected error occurred during imaging: {e}")
        return False, None

# --- Integrity Verification Step (P1 Feature) ---
def verify_integrity(original_source, image_file, log_path):
    """Verifies the integrity of the image by comparing hashes."""
    
    # 1. Hash the FINAL IMAGE (Second independent verification)
    image_hash = calculate_hash_from_file(image_file, HASH_ALGORITHM)
    
    # 2. Hash the ORIGINAL SOURCE (First independent verification)
    source_hash = calculate_hash_from_file(original_source, HASH_ALGORITHM)

    if not image_hash or not source_hash:
        print("ERROR: One or both hash calculations failed.")
        return False

    print(f"Original Source Hash ({HASH_ALGORITHM}): {source_hash}")
    print(f"Acquired Image Hash ({HASH_ALGORITHM}): {image_hash}")
    
    if source_hash == image_hash:
        # Proof of integrity for the Chain of Custody
        print("--- HASH MATCH: Image is a verifiable, forensically sound copy. ---")
        return True
    else:
        print("--- HASH MISMATCH: Image integrity compromised. DO NOT USE. ---")
        return False

# --- Example Usage (Main Execution Block) ---
if __name__ == '__main__':
    # >>> SAFETY WARNING: USE A TEST FILE, NOT A REAL DEVICE FOR PRACTICE <<<
    # On a real investigation, TEST_SOURCE would be '/dev/sdb' or '\\.\PhysicalDrive1'
    TEST_SOURCE = 'test_evidence.bin' 
    OUTPUT_FILE = 'forensic_image.dd'
    LOG_FILE = 'forensic_hash.log'
    
    # --- Setup the simulated source file (10MB of random data) ---
    if not os.path.exists(TEST_SOURCE):
        print(f"Creating mock evidence file: {TEST_SOURCE}")
        # Using Python to create the mock file safely
        with open(TEST_SOURCE, 'wb') as f:
            f.write(os.urandom(10 * 1024 * 1024)) # 10MB of random bytes
    
    # 1. Run the acquisition
    success, log_path = perform_forensic_imaging(TEST_SOURCE, OUTPUT_FILE, LOG_FILE)
    
    if success:
        # 2. Run the verification
        verification_success = verify_integrity(TEST_SOURCE, OUTPUT_FILE, log_path)
        
        if verification_success:
            print("\n✅ ACQUISITION ENGINE TEST PASSED.")
        else:
            print("\n❌ ACQUISITION ENGINE TEST FAILED (Hash Mismatch).")