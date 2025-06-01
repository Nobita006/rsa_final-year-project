"""
benchmark_rsa.py
----------------
Benchmark RSA key generation, encryption, and decryption using SageMath.
Logs all results into benchmark_output.txt in a specific, clean format,
focusing only on the time taken for each operation.

Task 1:
  - Run rsa_keygenerator.py repeatedly with key sizes starting from 512 bits,
    increasing by 256 bits up to 2048 bits.
  - After finishing Task 1, re-run the key generator with a fixed key size (1024 bits)
    so that the resulting public_key.csv and private_key.csv are used for Tasks 2 and 3.

Task 2:
  - Create plaintext files of increasing sizes: 1 KB, 10 KB, 100 KB, 1 MB, and 10MB.
  - Encrypt each plaintext file using rsa_encrypt.py (with the public key from Task 1).
  - Encrypt pre-existing sample files of different formats (docx, jpg, mov, mp3, mp4, pdf, png, ppt, pptx, txt).

Task 3:
  - Decrypt the ciphertext files (produced in Task 2) using rsa_decrypt.py (with the private key from Task 1).
  - Decrypt the ciphertexts of the pre-existing sample files.

Usage:
    python3 benchmark_rsa.py
"""

import subprocess
import random, string, sys, time
import os
import re # For more flexible time parsing

def run_command_and_get_script_time(cmd_list):
    """
    Run the given command and parse a line like 'Time taken...: X.XX seconds'
    from its stdout.
    Returns a tuple (parsed_time_str, total_popen_time_seconds).
    parsed_time_str will be like "X.XXXXXX seconds" or None.
    """
    print(f"Executing: {' '.join(cmd_list)}") # Keep console output for user
    start_popen_time = time.time()
    process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
    stdout, stderr = process.communicate()
    end_popen_time = time.time()
    total_popen_duration = end_popen_time - start_popen_time

    parsed_script_time_str = None
    if stdout:
        # More flexible regex to find "Time taken...: X.XXXXXX seconds"
        # It looks for "Time taken", then any characters (non-greedy), then a colon,
        # then spaces, then a floating point number, then " seconds".
        match = re.search(r"Time taken.*?:([\s]*[\d\.]+[\s]*)seconds", stdout, re.IGNORECASE)
        if match:
            try:
                time_val_str = match.group(1).strip() # Get the number part
                time_val_float = float(time_val_str)
                parsed_script_time_str = f"{time_val_float:.6f} seconds"
            except ValueError:
                # This should not happen if regex matches correctly, but as a safeguard
                print(f"Warning: Could not parse time from stdout line: '{match.group(0)}'")
                pass # Could not parse time from line

    # Only log to file if the command itself failed, not general stdout
    if process.returncode != 0:
        print(f"Command failed: {' '.join(cmd_list)}")
        if stdout.strip(): print(f"Stdout: {stdout.strip()}")
        if stderr.strip(): print(f"Stderr: {stderr.strip()}")
        # Log minimal failure info to benchmark_output.txt
        log_to_file(log_file_global, f"COMMAND FAILED: {' '.join(cmd_list)} (RC: {process.returncode})")
        if stderr.strip():
            log_to_file(log_file_global, f"  Error details: {stderr.strip().splitlines()[0] if stderr.strip().splitlines() else 'No stderr details'}") # Log first line of stderr
        return None, -1 # Indicate failure

    return parsed_script_time_str, total_popen_duration


def log_to_file(log_file, content):
    """Append content to the log file."""
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(content + "\n")

# Global log file variable
log_file_global = "benchmark_output.txt"

def create_dummy_text_file(filepath, size_bytes):
    """Creates a dummy text file with random alphanumeric characters if it doesn't exist or size differs."""
    if not os.path.exists(filepath) or os.path.getsize(filepath) != size_bytes:
        print(f"Creating/Updating dummy text file: {filepath} ({size_bytes / 1024:.2f} KB)")
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        content = ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=size_bytes))
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

def main():
    global log_file_global

    sage_cmd_prefix = ["sage"]
    keygenerator_script = "rsa_keygenerator.py"
    encrypt_script = "rsa_encrypt.py"
    decrypt_script = "rsa_decrypt.py"

    with open(log_file_global, "w", encoding="utf-8") as f:
        f.write("RSA Benchmark Results\n")
        f.write("=" * 50 + "\n\n")

    # --------------------------
    # Task 1: Key Generation
    # --------------------------
    print("=== Task 1: Key Generation Benchmarking ===") # Console output
    log_to_file(log_file_global, "Task 1: Key Generation Benchmarking") # File output
    log_to_file(log_file_global, "-" * 50)

    key_sizes_bits = list(range(512, 2048 + 1, 256))
    for ks in key_sizes_bits:
        cmd = sage_cmd_prefix + [keygenerator_script, str(ks)]
        # Console output for user progress
        print(f"\nBenchmarking key generation for key size {ks} bits...")
        
        parsed_time, _ = run_command_and_get_script_time(cmd)

        if parsed_time:
            log_to_file(log_file_global, f"Key size: {ks} bits | Time taken: {parsed_time}")
        else:
            log_to_file(log_file_global, f"Key size: {ks} bits | FAILED or time not parsed from script output")
    
    fixed_key_size = 1024
    print(f"\nBenchmarking key generation for fixed key size {fixed_key_size} bits (for Tasks 2 and 3)...")
    cmd_fixed_key = sage_cmd_prefix + [keygenerator_script, str(fixed_key_size)]
    parsed_time_fixed, _ = run_command_and_get_script_time(cmd_fixed_key)
    if parsed_time_fixed:
        log_to_file(log_file_global, f"Fixed key size: {fixed_key_size} bits | Time taken: {parsed_time_fixed}")
    else:
        log_to_file(log_file_global, f"Fixed key size: {fixed_key_size} bits | FAILED or time not parsed from script output")
    log_to_file(log_file_global, "\n")


    # --------------------------
    # Task 2: Encryption
    # --------------------------
    print("=== Task 2: Encryption Benchmarking ===") # Console output
    log_to_file(log_file_global, "Task 2: Encryption Benchmarking") # File output
    log_to_file(log_file_global, "-" * 50)

    message_sizes_text = {
        "1KB": 1 * 1024,
        "10KB": 10 * 1024,
        "100KB": 100 * 1024,
        "1MB": 1 * 1024 * 1024,
        "10MB": 10 * 1024 * 1024
    }
    
    for label, size in message_sizes_text.items():
        message_filename = f"message_{label}.txt"
        create_dummy_text_file(message_filename, size)
        
        print(f"\nBenchmarking encryption for {label} message ({message_filename})...") # Console
        cmd_encrypt = sage_cmd_prefix + [encrypt_script, message_filename, "public_key.csv"]
        parsed_time, _ = run_command_and_get_script_time(cmd_encrypt)
        
        if parsed_time:
            log_to_file(log_file_global, f"Message size: {label} | Encryption time: {parsed_time}")
        else:
            log_to_file(log_file_global, f"Message size: {label} | Encryption FAILED or time not parsed")

    other_files_to_encrypt = [
        "test.txt", "test.docx", "test.jpg", "test.mov", "test.mp3",
        "test.mp4", "test.pdf", "test.png", "test.ppt"
    ]

    for filename in other_files_to_encrypt:
        if not os.path.exists(filename):
            print(f"File {filename} not found for encryption. Skipping.") # Console
            log_to_file(log_file_global, f"File: {filename} | Encryption SKIPPED (File not found)") # File
            continue

        file_size = os.path.getsize(filename)
        file_label_log = f"File ({filename}, {file_size} bytes)" # For logging to file

        print(f"\nBenchmarking encryption for {filename} (size: {file_size} bytes)...") # Console
        cmd_encrypt_other = sage_cmd_prefix + [encrypt_script, filename, "public_key.csv"]
        parsed_time, _ = run_command_and_get_script_time(cmd_encrypt_other)

        if parsed_time:
            log_to_file(log_file_global, f"{file_label_log} | Encryption time: {parsed_time}")
        else:
            log_to_file(log_file_global, f"{file_label_log} | Encryption FAILED or time not parsed")
    log_to_file(log_file_global, "\n")


    # --------------------------
    # Task 3: Decryption
    # --------------------------
    print("=== Task 3: Decryption Benchmarking ===") # Console
    log_to_file(log_file_global, "Task 3: Decryption Benchmarking") # File
    log_to_file(log_file_global, "-" * 50)

    for label in message_sizes_text.keys():
        original_text_filename = f"message_{label}.txt"
        base_name, ext = os.path.splitext(original_text_filename)
        ciphertext_filename = f"{base_name}_cipher{ext}"

        if not os.path.exists(ciphertext_filename):
            print(f"Ciphertext file {ciphertext_filename} not found for decryption (for {label}). Skipping.")
            log_to_file(log_file_global, f"Message size: {label} | Decryption SKIPPED (Ciphertext {ciphertext_filename} not found)")
            continue
        
        print(f"\nBenchmarking decryption for {label} message (from {ciphertext_filename})...") # Console
        cmd_decrypt = sage_cmd_prefix + [decrypt_script, ciphertext_filename, "private_key.csv"]
        parsed_time, _ = run_command_and_get_script_time(cmd_decrypt)

        if parsed_time:
            log_to_file(log_file_global, f"Message size: {label} | Decryption time: {parsed_time}")
        else:
            log_to_file(log_file_global, f"Message size: {label} | Decryption FAILED or time not parsed")

    for original_filename in other_files_to_encrypt: 
        base_name, ext = os.path.splitext(original_filename)
        ciphertext_filename_other = f"{base_name}_cipher{ext}" 

        if not os.path.exists(ciphertext_filename_other):
            print(f"Ciphertext file {ciphertext_filename_other} not found for decryption (for {original_filename}). Skipping.")
            log_to_file(log_file_global, f"File ({original_filename}) | Decryption SKIPPED (Ciphertext {ciphertext_filename_other} not found)")
            continue

        cipher_file_size = os.path.getsize(ciphertext_filename_other)
        file_label_dec_log = f"File ({original_filename}, from cipher {cipher_file_size} bytes)" # For logging

        print(f"\nBenchmarking decryption for {original_filename} (from {ciphertext_filename_other})...") # Console
        cmd_decrypt_other = sage_cmd_prefix + [decrypt_script, ciphertext_filename_other, "private_key.csv"]
        parsed_time, _ = run_command_and_get_script_time(cmd_decrypt_other)

        if parsed_time:
            log_to_file(log_file_global, f"{file_label_dec_log} | Decryption time: {parsed_time}")
        else:
            log_to_file(log_file_global, f"{file_label_dec_log} | Decryption FAILED or time not parsed")
    log_to_file(log_file_global, "\n")


    print("Benchmarking completed.") # Console
    log_to_file(log_file_global, "Benchmarking completed.\n") # File
    print(f"Results have been logged to {log_file_global}") # Console

if __name__ == "__main__":
    main()