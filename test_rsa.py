#!/usr/bin/env python3
"""
test_rsa.py
-----------
Comprehensive test driver for RSA key generation, encryption, and decryption
using SageMath scripts.

This driver runs tests for:
  - Different key sizes.
  - Various message/file sizes (text and binary).
  - Specific file types (as provided by user).
  - Edge cases like key sizes too small for padding.
  - Robustness against missing key files.

Usage:
    python3 test_rsa.py

Imp: Place your test files (e.g., test.docx, test.jpg, test.txt, etc.) 
     in the same directory as this test_rsa.py script.

Note: Output from the underlying RSA scripts is printed.
      A summary of test results is provided at the end.
"""

import subprocess
import os
import sys
import random
import string
import shutil # For managing test directory

# --- Configuration ---
SAGE_CMD = "sage"
TEST_DIR_NAME = "rsa_test_workspace" # Directory for temporary test files
# Script names (will be resolved to absolute paths)
KEY_GENERATOR_SCRIPT_NAME = "rsa_keygenerator.py"
ENCRYPT_SCRIPT_NAME = "rsa_encrypt.py"
DECRYPT_SCRIPT_NAME = "rsa_decrypt.py"

# ANSI Colors
class Colors:
    HEADER = '\033[95m'    # Purple
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'   # Green
    WARNING = '\033[93m'   # Yellow
    FAIL = '\033[91m'      # Red
    ENDC = '\033[0m'       # Reset
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    INFO = '\033[94m'      # Blue for info

def cprint(color, message):
    print(f"{color}{message}{Colors.ENDC}")

# --- Global paths for scripts (resolved in setup) ---
KEY_GENERATOR_SCRIPT_PATH = ""
ENCRYPT_SCRIPT_PATH = ""
DECRYPT_SCRIPT_PATH = ""

# --- Helper Functions ---

def run_command(cmd_list, expect_error=False, check_output_for_error=True):
    cprint(Colors.OKCYAN, f"  Executing: {' '.join(cmd_list)}")
    try:
        # Ensure text=True and specify encoding for Popen/run
        result = subprocess.run(cmd_list, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=600)
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""

        if stdout:
            print(f"    {Colors.INFO}STDOUT:{Colors.ENDC}\n      {stdout.replace(chr(10), chr(10) + '      ')}")
        if stderr:
            print(f"    {Colors.WARNING}STDERR:{Colors.ENDC}\n      {stderr.replace(chr(10), chr(10) + '      ')}")

        # Check for "Error:" or "Traceback" (more robust for Sage errors)
        has_error_in_output = "Error:" in stdout or "Error:" in stderr or "Traceback (most recent call last):" in stderr

        if expect_error:
            if result.returncode != 0 or (check_output_for_error and has_error_in_output):
                cprint(Colors.OKGREEN, "    OK: Expected error/failure occurred.")
                return True
            else:
                cprint(Colors.FAIL, "    FAIL: Expected an error but command succeeded or no 'Error:'/'Traceback' in output.")
                return False
        else:
            if result.returncode == 0 and not (check_output_for_error and has_error_in_output):
                return True
            else:
                cprint(Colors.FAIL, f"    FAIL: Command failed or 'Error:'/'Traceback' in output. Return code: {result.returncode}")
                return False
    except subprocess.TimeoutExpired:
        cprint(Colors.FAIL, "    FAIL: Command timed out after 10 minutes.")
        return False
    except Exception as e:
        cprint(Colors.FAIL, f"    FAIL: Exception during command execution: {e}")
        return False

def create_test_file_from_content(filename, content, binary_mode=False):
    filepath = os.path.join(".", filename) # Assumes CWD is TEST_DIR
    mode = "wb" if binary_mode else "w"
    encoding = None if binary_mode else "utf-8"
    with open(filepath, mode, encoding=encoding) as f:
        f.write(content)
    return filepath

def copy_test_file(source_path, dest_filename):
    """Copies a file from source_path (outside TEST_DIR) to dest_filename (inside TEST_DIR)."""
    dest_path = os.path.join(".", dest_filename) # Assumes CWD is TEST_DIR
    try:
        shutil.copy2(source_path, dest_path)
        cprint(Colors.INFO, f"    Copied '{source_path}' to '{dest_path}' for testing.")
        return dest_path
    except FileNotFoundError:
        cprint(Colors.WARNING, f"    WARNING: Source file for copy not found: '{source_path}'. Skipping this specific file test.")
        return None
    except Exception as e:
        cprint(Colors.WARNING, f"    WARNING: Could not copy file '{source_path}': {e}. Skipping this specific file test.")
        return None


def compare_files(file1_path, file2_path):
    try:
        with open(file1_path, "rb") as f1, open(file2_path, "rb") as f2:
            bytes1 = f1.read()
            bytes2 = f2.read()
        return bytes1 == bytes2
    except FileNotFoundError:
        cprint(Colors.WARNING, f"    Comparison Error: One or both files not found: '{file1_path}', '{file2_path}'")
        return False
    except Exception as e:
        cprint(Colors.WARNING, f"    Comparison Error: {e}")
        return False

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation + " ", k=length))

def generate_random_bytes(length):
    return os.urandom(length)

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def record_pass(self, test_name):
        cprint(Colors.OKGREEN, f"  PASSED: {test_name}")
        self.passed += 1

    def record_fail(self, test_name, reason=""):
        cprint(Colors.FAIL, f"  FAILED: {test_name} {(': ' + reason) if reason else ''}")
        self.failed += 1
    
    def record_skip(self, test_name, reason=""):
        cprint(Colors.OKCYAN, f"  SKIPPED: {test_name} {(': ' + reason) if reason else ''}")
        self.skipped +=1

    def summary(self):
        cprint(Colors.HEADER, "\n--- Test Summary ---")
        total_run = self.passed + self.failed
        cprint(Colors.INFO, f"Total Tests Attempted: {total_run + self.skipped}")
        cprint(Colors.OKGREEN, f"Passed: {self.passed}")
        cprint(Colors.FAIL, f"Failed: {self.failed}")
        if self.skipped > 0:
            cprint(Colors.OKCYAN, f"Skipped: {self.skipped}")
        
        if self.failed > 0:
            cprint(Colors.FAIL, "\n!!! SOME TESTS FAILED !!!")
            return False
        elif total_run == 0 and self.skipped > 0:
             cprint(Colors.WARNING, "\n!!! NO TESTS EXECUTED (ALL SKIPPED) !!!")
             return False # Still considered a failure if nothing ran
        cprint(Colors.OKGREEN, "\nAll executed tests passed successfully!")
        return True

def run_encryption_decryption_test(test_name, results,
                                   public_key_file, private_key_file,
                                   file_content=None, input_file_to_copy_path=None, 
                                   binary_mode=False, original_filename_override=None):
    cprint(Colors.HEADER, f"\n--- Test Case: {test_name} ---")
    
    if input_file_to_copy_path:
        original_filename = os.path.basename(input_file_to_copy_path)
        original_filepath_in_testdir = copy_test_file(input_file_to_copy_path, original_filename)
        if not original_filepath_in_testdir:
            results.record_skip(test_name, f"Input file '{input_file_to_copy_path}' could not be copied or found.")
            return
        binary_mode = True # Actual files are treated as binary for I/O
    elif file_content is not None:
        default_ext = ".dat" if binary_mode else ".txt"
        original_filename = original_filename_override or f"{test_name.lower().replace(' ', '_').replace('(', '').replace(')','')}{default_ext}"
        original_filepath_in_testdir = create_test_file_from_content(original_filename, file_content, binary_mode)
    else:
        results.record_fail(test_name, "No file content or path provided.")
        return

    # 1. Encryption
    print("  Phase 1: Encryption")
    cmd_encrypt = [SAGE_CMD, ENCRYPT_SCRIPT_PATH, original_filename, public_key_file]
    if not run_command(cmd_encrypt):
        results.record_fail(f"{test_name} - Encryption Process Failed")
        return

    base, ext = os.path.splitext(original_filename)
    ciphertext_filename = f"{base}_cipher{ext}"
    ciphertext_filepath = os.path.join(".", ciphertext_filename) # CWD is TEST_DIR

    if not os.path.exists(ciphertext_filepath):
        results.record_fail(f"{test_name} - Ciphertext file '{ciphertext_filename}' not created")
        return

    # 2. Decryption
    print("\n  Phase 2: Decryption")
    cmd_decrypt = [SAGE_CMD, DECRYPT_SCRIPT_PATH, ciphertext_filename, private_key_file]
    if not run_command(cmd_decrypt):
        results.record_fail(f"{test_name} - Decryption Process Failed")
        return

    # Determine expected decrypted filename based on how rsa_decrypt.py names its output
    # Assuming rsa_decrypt.py creates <original_base_name_without_cipher>_decrypted.<original_ext>
    # e.g., if ciphertext is "file_cipher.txt", decrypted is "file_decrypted.txt"
    base_cipher, ext_original = os.path.splitext(ciphertext_filename) 
    if base_cipher.endswith("_cipher"):
        dec_base = base_cipher[:-len("_cipher")] + "_decrypted" 
    else: # Fallback if _cipher is not in the name (less likely with current setup)
        dec_base = base_cipher + "_decrypted"
    decrypted_filename = f"{dec_base}{ext_original}"
    decrypted_filepath = os.path.join(".", decrypted_filename) # CWD is TEST_DIR

    if not os.path.exists(decrypted_filepath):
        results.record_fail(f"{test_name} - Decrypted file '{decrypted_filename}' not created")
        return

    # 3. Comparison
    print("\n  Phase 3: Comparison")
    if compare_files(original_filepath_in_testdir, decrypted_filepath):
        results.record_pass(test_name)
    else:
        results.record_fail(f"{test_name} - File content mismatch after decryption")


def setup_test_environment(project_root_dir):
    global TEST_DIR_NAME, KEY_GENERATOR_SCRIPT_PATH, ENCRYPT_SCRIPT_PATH, DECRYPT_SCRIPT_PATH
    
    test_dir_abs_path = os.path.join(project_root_dir, TEST_DIR_NAME)
    
    if os.path.exists(test_dir_abs_path):
        cprint(Colors.WARNING, f"Cleaning up existing test directory: {test_dir_abs_path}")
        shutil.rmtree(test_dir_abs_path)
    os.makedirs(test_dir_abs_path)
    cprint(Colors.OKGREEN, f"Created test directory: {test_dir_abs_path}")
    
    os.chdir(test_dir_abs_path) # Change CWD for subprocesses
    cprint(Colors.INFO, f"Changed CWD to: {os.getcwd()}")

    KEY_GENERATOR_SCRIPT_PATH = os.path.join(project_root_dir, KEY_GENERATOR_SCRIPT_NAME)
    ENCRYPT_SCRIPT_PATH = os.path.join(project_root_dir, ENCRYPT_SCRIPT_NAME)
    DECRYPT_SCRIPT_PATH = os.path.join(project_root_dir, DECRYPT_SCRIPT_NAME)

    for script_path in [KEY_GENERATOR_SCRIPT_PATH, ENCRYPT_SCRIPT_PATH, DECRYPT_SCRIPT_PATH]:
        if not os.path.exists(script_path):
            cprint(Colors.FAIL, f"CRITICAL ERROR: Script not found: {script_path}")
            cprint(Colors.FAIL, "Make sure test_rsa.py is in the project root with rsa_*.py scripts, or adjust paths.")
            sys.exit(1)

def main():
    project_root_dir = os.path.dirname(os.path.abspath(__file__))
    original_cwd = os.getcwd() 

    setup_test_environment(project_root_dir)
    
    results = TestResult()

    cprint(Colors.BOLD + Colors.HEADER, "\n===== RSA IMPLEMENTATION TEST SUITE =====\n")

    # --- Test Group 1: Standard Key Size (1024-bit primes) ---
    cprint(Colors.HEADER, "--- GROUP 1: Standard Key Size (1024-bit primes) ---")
    key_size_1024 = 1024 # Key size for rsa_keygenerator.py (prime size)
    target_public_key_1024 = "public_key_1024.csv"
    target_private_key_1024 = "private_key_1024.csv"
    default_pk = "public_key.csv" 
    default_sk = "private_key.csv"

    cprint(Colors.INFO, f"Generating {key_size_1024}-bit keys...")
    keys_1024_generated_ok = False
    if not run_command([SAGE_CMD, KEY_GENERATOR_SCRIPT_PATH, str(key_size_1024)]):
        results.record_fail(f"Key Generation ({key_size_1024}-bit primes)")
    else:
        try:
            if os.path.exists(default_pk) and os.path.exists(default_sk):
                os.rename(default_pk, target_public_key_1024)
                os.rename(default_sk, target_private_key_1024)
                results.record_pass(f"Key Generation & Renaming ({key_size_1024}-bit primes)")
                keys_1024_generated_ok = True
            else:
                results.record_fail(f"Key Generation ({key_size_1024}-bit primes) - Default key files not found after generation.")
        except Exception as e_rename:
            results.record_fail(f"Key Generation ({key_size_1024}-bit primes) - Error renaming: {e_rename}")

    if keys_1024_generated_ok:
        # Assuming primes of 1024 bits, N is ~2048 bits.
        # OAEP padding for SHA256 uses 2*hLen + 2 bytes. hLen for SHA256 is 32 bytes.
        # So, 2*32 + 2 = 66 bytes of overhead.
        # Max message per block = (2048/8) - 66 = 256 - 66 = 190 bytes.
        # For safety and simplicity, let's use a slightly smaller data_area.
        data_area_1024 = 180 

        synthetic_text_tests = [
            ("Exact Size Text", generate_random_string(data_area_1024)),
            ("Smaller Text", generate_random_string(data_area_1024 - 10)),
            ("Larger Text (2 blocks)", generate_random_string(data_area_1024 + 50)), # Ensure it goes over one block
            ("Very Small Text", "RSA Test!"),
            ("Medium Text (5KB)", generate_random_string(5 * 1024)),
        ]
        for name, content in synthetic_text_tests:
            run_encryption_decryption_test(f"{name} (1024-bit key)", results,
                                           public_key_file=target_public_key_1024,
                                           private_key_file=target_private_key_1024,
                                           file_content=content, binary_mode=False)
        
        synthetic_binary_tests = [
            ("Small Binary (1KB)", generate_random_bytes(1 * 1024)),
            ("Medium Binary (100KB)", generate_random_bytes(100 * 1024)),
        ]
        for name, content in synthetic_binary_tests:
            run_encryption_decryption_test(f"{name} (1024-bit key)", results,
                                           public_key_file=target_public_key_1024,
                                           private_key_file=target_private_key_1024,
                                           file_content=content, binary_mode=True)

        # Test with actual files provided by user
        # IMPORTANT: These files must exist in the same directory as test_rsa.py
        actual_files_to_test = [
            "test.txt", "test.docx", "test.jpg", "test.mov", "test.mp3",
            "test.mp4", "test.pdf", "test.png", "test.ppt"
        ]
        for filename in actual_files_to_test:
            source_file_path = os.path.join(project_root_dir, filename) 
            run_encryption_decryption_test(f"Actual File: {filename} (1024-bit key)", results,
                                           public_key_file=target_public_key_1024,
                                           private_key_file=target_private_key_1024,
                                           input_file_to_copy_path=source_file_path)
    else:
        results.record_skip("All Group 1 Encryption/Decryption Tests", "1024-bit prime key generation failed.")

    # --- Test Group 2: Small Key Size ---
    cprint(Colors.HEADER, "\n--- GROUP 2: Small Key Size (e.g., 64-bit primes, Expecting Encryption Failure with OAEP) ---")
    # For RSA with OAEP, the message length mLen must satisfy mLen <= k - 2hLen - 2
    # k = modulus byte length. For 64-bit primes, N is ~128 bits = 16 bytes.
    # hLen for SHA256 = 32 bytes. So, k - 2hLen - 2 = 16 - 2*32 - 2 = 16 - 64 - 2 = -50 bytes.
    # This means encryption should fail because message length cannot be negative.
    key_size_prime_64 = 64 
    target_public_key_64 = "public_key_64.csv"

    cprint(Colors.INFO, f"Generating {key_size_prime_64}-bit prime keys...")
    keys_64_generated_ok = False
    if not run_command([SAGE_CMD, KEY_GENERATOR_SCRIPT_PATH, str(key_size_prime_64)]):
        results.record_fail(f"Key Generation ({key_size_prime_64}-bit primes)")
    else:
        try:
            if os.path.exists(default_pk):
                os.rename(default_pk, target_public_key_64)
                if os.path.exists(default_sk): os.remove(default_sk) # Clean up unused private key
                results.record_pass(f"Key Generation & Renaming ({key_size_prime_64}-bit primes)")
                keys_64_generated_ok = True
            else:
                results.record_fail(f"Key Generation ({key_size_prime_64}-bit primes) - Default public key not found.")
        except Exception as e_rename_64:
            results.record_fail(f"Key Generation ({key_size_prime_64}-bit primes) - Error renaming: {e_rename_64}")

    if keys_64_generated_ok:
        cprint(Colors.INFO, "  Attempting encryption with small key (expected to fail due to OAEP constraints)...")
        dummy_filename_small_key = "dummy_for_small_key_test.txt"
        create_test_file_from_content(dummy_filename_small_key, "test") # Content doesn't matter much, OAEP check is first
        
        cmd_encrypt_small = [SAGE_CMD, ENCRYPT_SCRIPT_PATH, dummy_filename_small_key, target_public_key_64]
        # Expect an error message from rsa_encrypt.py like "ValueError: Plaintext is too long." or similar
        if run_command(cmd_encrypt_small, expect_error=True, check_output_for_error=True):
            results.record_pass("Encryption Failure with Small Key (Expected due to OAEP)")
        else:
            results.record_fail("Encryption Failure with Small Key (ERROR: Succeeded or no error message)")
    else:
        results.record_skip("Small Key Encryption Test", f"{key_size_prime_64}-bit prime key generation failed.")

    # --- Test Group 3: Key File Issues ---
    cprint(Colors.HEADER, "\n--- GROUP 3: Key File Handling Tests ---")
    if keys_1024_generated_ok: 
        test_file_for_key_issues = "message_for_key_issues.txt"
        create_test_file_from_content(test_file_for_key_issues, "Test content.")

        cprint(Colors.INFO, "  Test: Encryption with non-existent public key file")
        cmd_enc_bad_pub = [SAGE_CMD, ENCRYPT_SCRIPT_PATH, test_file_for_key_issues, "non_existent_public.csv"]
        if run_command(cmd_enc_bad_pub, expect_error=True, check_output_for_error=True):
            results.record_pass("Encryption with Non-existent Public Key")
        else:
            results.record_fail("Encryption with Non-existent Public Key")
        
        plain_for_valid_cipher = "plain_for_valid_cipher.txt"
        create_test_file_from_content(plain_for_valid_cipher, "abc") # Small content

        cprint(Colors.INFO, "  Generating temporary valid ciphertext for next test...")
        # Use the existing 1024-bit public key for this
        cmd_temp_encrypt = [SAGE_CMD, ENCRYPT_SCRIPT_PATH, plain_for_valid_cipher, target_public_key_1024]
        if run_command(cmd_temp_encrypt): # Should succeed
            expected_temp_cipher_name = f"{os.path.splitext(plain_for_valid_cipher)[0]}_cipher{os.path.splitext(plain_for_valid_cipher)[1]}"
            if os.path.exists(expected_temp_cipher_name):
                cprint(Colors.INFO, "\n  Test: Decryption with non-existent private key file")
                cmd_dec_bad_priv = [SAGE_CMD, DECRYPT_SCRIPT_PATH, expected_temp_cipher_name, "non_existent_private.csv"]
                if run_command(cmd_dec_bad_priv, expect_error=True, check_output_for_error=True):
                    results.record_pass("Decryption with Non-existent Private Key")
                else:
                    results.record_fail("Decryption with Non-existent Private Key")
            else:
                results.record_skip("Decryption with Non-existent Private Key", f"Temp cipher file '{expected_temp_cipher_name}' not created during setup.")
        else:
            results.record_skip("Decryption with Non-existent Private Key", "Failed to create temp cipher file for this test.")
    else:
        results.record_skip("All Key File Handling Tests", "1024-bit prime keys not available from Group 1.")

    # --- Final Summary ---
    all_passed = results.summary()
    
    os.chdir(original_cwd) 
    test_dir_abs_path = os.path.join(project_root_dir, TEST_DIR_NAME)
    # Clean up test directory only if all tests passed, otherwise keep for inspection
    if all_passed and results.skipped == 0 : # Only clean if all passed AND nothing was skipped
         cprint(Colors.OKGREEN, f"Cleaning up test directory: {test_dir_abs_path}")
         shutil.rmtree(test_dir_abs_path)
    else:
         cprint(Colors.WARNING, f"Test directory '{test_dir_abs_path}' retained due to failures or skips.")

    if not all_passed:
        sys.exit(1)

if __name__ == "__main__":
    main()