#!/usr/bin/env sage -python
"""
rsa_decrypt.py
--------------
Usage:
    sage rsa_decrypt.py <ciphertext_filename> <private_key_csv>
Example:
    sage rsa_decrypt.py 'Cover Letter_cipher.pdf' 'private_key.csv'
    sage rsa_decrypt.py 'image_cipher.png' 'private_key.csv'

Decrypts an RSA-encrypted ciphertext file (which contains one integer per line)
using a private key stored in a CSV file, reconstructing the original binary file.

Each ciphertext integer corresponds to a fixed-size block of length block_size, where:
    block_size = (n.nbits() - 1) // 8.
After decryption, the block is interpreted as follows:
  - The first byte (header) gives L, the actual length of the original data chunk in this block.
  - The next L bytes are the true data chunk.
  - The remaining bytes are random padding and are discarded.
The recovered data chunks are concatenated and then written to an output file in binary mode.
"""

from sage.all import *
import sys, os, time, csv

def usage():
    print("Usage: sage rsa_decrypt.py <ciphertext_filename> <private_key_csv>")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()
    
    ciphertext_filename = sys.argv[1]
    private_key_csv = sys.argv[2]
    
    # Read private key (d, n) from CSV.
    try:
        with open(private_key_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            row = next(reader)
            if len(row) < 2:
                print("Error: Invalid private key file format.")
                sys.exit(1)
            d = Integer(row[0]) # Renamed from 'd' to avoid potential clash if 'd' used as loop var
            n = Integer(row[1])
    except FileNotFoundError:
        print(f"Error: Private key file '{private_key_csv}' not found.")
        sys.exit(1)
    except Exception as ex:
        print(f"Error reading private key CSV file '{private_key_csv}': {ex}")
        sys.exit(1)
    
    if not os.path.exists(ciphertext_filename):
        print(f"Error: Ciphertext file '{ciphertext_filename}' does not exist.")
        sys.exit(1)
    
    # Determine block size based on n from the private key.
    block_size = (n.nbits() - 1) // 8
    # print("Block size determined from key:", block_size) # Kept commented
    if block_size < 15: # Must be consistent with encryption padding (1 byte L + 14 bytes tail)
        print("Error: Block size derived from key is too small (must be at least 15 bytes).")
        print(f"       Calculated block_size: {block_size} bytes. This might indicate a key mismatch or corruption.")
        sys.exit(1)
    # data_size = block_size - 15 # Not strictly needed for decryption logic itself, but good for consistency check.
    
    # Read ciphertext file (which contains integers, one per line).
    encrypted_blocks = []
    try:
        with open(ciphertext_filename, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line: # Skip empty lines
                    continue
                try:
                    c_int = Integer(line)
                    encrypted_blocks.append(c_int)
                except Exception as ex_parse: # More specific error for parsing
                    print(f"Error parsing line {line_num} in '{ciphertext_filename}': '{line}'. Not a valid integer. Error: {ex_parse}")
                    sys.exit(1)
    except Exception as ex:
        print(f"Error reading ciphertext file '{ciphertext_filename}': {ex}")
        sys.exit(1)
    
    if not encrypted_blocks:
        print(f"Warning: Ciphertext file '{ciphertext_filename}' is empty or contains no valid ciphertext lines.")
        # Decide if this is an error or if an empty output file is acceptable
        # For now, let's create an empty output file if the input was empty.
        
    all_decrypted_bytes_list = [] # Use a list to append byte strings, then join for efficiency
    dec_start_time = time.time()
    
    # print("=== Decrypting Blocks ===") # Kept commented
    for i, c_int in enumerate(encrypted_blocks):
        m_int = power_mod(c_int, d, n)
        
        # Convert decrypted integer back to a full block (block_size bytes).
        try:
            block_bytes = int(m_int).to_bytes(block_size, byteorder="big")
        except OverflowError:
            print(f"Error: Decrypted integer for block {i+1} ({m_int}) is too large to fit into {block_size} bytes.")
            print("       This likely indicates a key mismatch or corrupted ciphertext.")
            sys.exit(1)
            
        # Extract header (first byte): actual data length L.
        L = block_bytes[0]
        
        # Sanity check for L
        if 1 + L > block_size:
            print(f"Error: Invalid data length L={L} found in header of decrypted block {i+1}.")
            print(f"       L cannot cause data part (1+L) to exceed block_size ({block_size}).")
            print("       This might indicate data corruption or use of an incorrect decryption key.")
            sys.exit(1)
            
        # Extract the actual data bytes: next L bytes.
        data_part = block_bytes[1:1+L] # Changed from message_part
        all_decrypted_bytes_list.append(data_part)
        
        # # Print intermediate block details for demonstration.
        # # Useful for debugging the de-padding and block reconstruction.
        # print(f"\nBlock {i+1}/{len(encrypted_blocks)}:")
        # print(f"  Ciphertext Integer: {c_int}")
        # print(f"  Decrypted Integer (m_int): {m_int}")
        # print(f"  Decrypted Block Bytes ({len(block_bytes)} bytes, hex): {block_bytes.hex()[:80]}..." if len(block_bytes) > 40 else block_bytes.hex())
        # print(f"  Extracted L from header: {L}")
        # print(f"  Extracted Data Part ({len(data_part)} bytes): {data_part.hex()[:60]}..." if len(data_part) > 30 else data_part.hex())
        
    dec_end_time = time.time()

    final_decrypted_bytes = b"".join(all_decrypted_bytes_list)
    
    # Prepare output filename.
    # Aim to convert 'input_cipher.ext' to 'input_decrypted.ext'
    # or 'input_cipher' to 'input_decrypted'
    base, ext = os.path.splitext(ciphertext_filename)
    if base.endswith("_cipher"):
        original_base = base[:-len("_cipher")] # Remove '_cipher' suffix
    else:
        # If '_cipher' is not found, it might be an unusually named file.
        # We'll just append '_decrypted' to the current base.
        original_base = base 
        print(f"Warning: Ciphertext filename '{ciphertext_filename}' does not follow the expected '*_cipher.ext' pattern.")
    
    output_filename = f"{original_base}_decrypted{ext}"
    
    try:
        with open(output_filename, "wb") as f: # Write as binary
            f.write(final_decrypted_bytes)
    except Exception as ex:
        print(f"Error writing decrypted file '{output_filename}': {ex}")
        sys.exit(1)
    
    print("\nDecryption complete.")
    print(f"Decrypted file: {output_filename}")
    print(f"Decrypted file size: {len(final_decrypted_bytes)} bytes")
    print(f"Number of blocks processed: {len(encrypted_blocks)}")
    print(f"Time taken to decrypt: {dec_end_time - dec_start_time:.6f} seconds")

if __name__ == "__main__":
    main()
