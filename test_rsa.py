#!/usr/bin/env python3
"""
test_rsa.py
-----------
Test driver for RSA key generation, encryption, and decryption using SageMath.

This driver runs two groups of tests:

Group 1 (Normal key size 1024):
  - Runs key generation with key size 1024.
  - Computes block_size = ((1024*2) - 1) // 8 and data_area = block_size - 15.
  - Then runs encryption and decryption on messages with different sizes:
       * Message length exactly equal to data_area.
       * One byte smaller than data_area.
       * One byte larger than data_area.
       * A very small message.
       * A very large message (1 MB).
       
Group 2 (Small key size 64):
  - Runs key generation with key size 64.
  - Computes block_size = ((64*2)-1)//8 (which yields 15) so data_area becomes 0.
  - Then attempts to run encryption/decryption with a dummy message,
    which is expected to fail.
    
Usage:
    python3 test_rsa.py

Note: All output from the underlying RSA scripts (key generation, encryption, decryption)
      is printed to the console.
"""

import subprocess, os, sys, random, string

def run_command(cmd, expect_error=False):
    """Run a command using subprocess.run() without suppressing output."""
    print("\nRunning command:")
    print(cmd)
    result = subprocess.run(cmd, shell=True)
    if expect_error:
        if result.returncode == 0:
            print("ERROR: Expected an error but command succeeded:", cmd)
            sys.exit(1)
        else:
            print("Expected error occurred for:", cmd)
    else:
        if result.returncode != 0:
            print("ERROR: Command failed:", cmd)
            sys.exit(1)
    return result

def compute_data_area(key_size):
    """
    Compute block_size and data_area based on the key size.
    The RSA key generator produces keys such that modulus n has ~2*key_size bits.
    Then we define:
       block_size = ((key_size * 2) - 1) // 8
       data_area = block_size - 15
    """
    block_size = ((key_size * 2) - 1) // 8
    data_area = block_size - 15
    return block_size, data_area

def run_test(message_text, test_label):
    """
    Run encryption and decryption on the provided message_text.
    The keys are assumed to be already generated.
    """
    message_filename = f"message_{test_label}.txt"
    with open(message_filename, "w", encoding="utf-8") as f:
        f.write(message_text)
    
    # Run encryption.
    # Added quotes around filenames for robustness if they ever contain spaces
    cmd_encrypt = f"sage rsa_encrypt.py '{message_filename}' public_key.csv"
    run_command(cmd_encrypt)
    
    # Compute expected ciphertext file name.
    base, ext = os.path.splitext(message_filename)
    ciphertext_filename = f"{base}_cipher{ext}" if ext else f"{message_filename}_cipher"
    
    # Run decryption.
    cmd_decrypt = f"sage rsa_decrypt.py '{ciphertext_filename}' private_key.csv"
    run_command(cmd_decrypt)
    
    # Compute decrypted file name based on how rsa_decrypt.py names it
    base_cipher, ext_cipher = os.path.splitext(ciphertext_filename)
    if base_cipher.endswith("_cipher"):
        original_base_from_cipher = base_cipher[:-len("_cipher")]
    else:
        # This case should ideally not be hit if encrypt script is consistent
        original_base_from_cipher = base_cipher 
    decrypted_filename = f"{original_base_from_cipher}_decrypted{ext_cipher}"
    
    # Compare the original and decrypted messages.
    with open(message_filename, "r", encoding="utf-8") as f:
        original = f.read()
    if not os.path.exists(decrypted_filename):
        print(f"ERROR: Decrypted file '{decrypted_filename}' was not created.")
        sys.exit(1) # Make sure this exit actually stops the current test run
    with open(decrypted_filename, "r", encoding="utf-8") as f:
        decrypted = f.read()
    
    if original == decrypted:
        print(f"SUCCESS ({test_label}): Decrypted text matches the original!")
    else:
        print(f"FAILURE ({test_label}): Decrypted text does not match the original.")
        # For very large files, printing the whole content might be too much.
        # Consider printing only a snippet or lengths if they differ.
        if len(original) < 500 and len(decrypted) < 500: # Only print if reasonably small
            print("Original:", repr(original[:200])) # Print representation to see hidden chars
            print("Decrypted:", repr(decrypted[:200]))
        else:
            print(f"Original length: {len(original)}, Decrypted length: {len(decrypted)}")
            
def main():
    print("=== Group 1: Normal Key Size (1024 bits) ===")
    # Run key generation for 1024-bit keys.
    run_command("sage rsa_keygenerator.py 1024")
    # Compute block_size and data_area.
    block_size, data_area = compute_data_area(1024)
    print(f"Computed block_size = {block_size}, data_area = {data_area} bytes")
    
    # Test messages for Group 1.
    tests = [
        ("exact", "X" * data_area),            # Exactly equal to data_area.
        ("one_smaller", "Y" * (data_area - 1)),  # One byte smaller.
        ("one_larger", "Z" * (data_area + 1)),   # One byte larger (should split into two blocks).
        ("very_small", "HelloRSA!X"),           # Very small message (~10 bytes).
        ("very_large", ''.join(random.choices(string.ascii_letters + string.digits, k=1048576)))  # 1 MB message.
    ]
    
    for label, msg in tests:
        print(f"\n--- Test: {label} (Message length: {len(msg)} bytes) ---")
        try:
            run_test(msg, label)
        except SystemExit as e:
            print(f"Test '{label}' failed with exit code {e}. Continuing to next test.")
        except Exception as e:
            print(f"Test '{label}' raised an unexpected exception: {e}. Continuing to next test.")

    print("\n=== Group 2: Small Key Size (64 bits) ===")
    # Run key generation for 64-bit keys.
    run_command("sage rsa_keygenerator.py 64")
    # For key_size=64, compute block_size and data_area.
    block_size_small, data_area_small = compute_data_area(64)
    print(f"Computed block_size = {block_size_small}, data_area = {data_area_small} bytes")
    # Use a dummy message.
    dummy_message = "Test"
    print("\n--- Test: small_key (Expected to fail encryption/decryption due to insufficient block size) ---")
    cmd_encrypt = f"sage rsa_encrypt.py message_small_key.txt public_key.csv"
    # Create dummy message file.
    with open("message_small_key.txt", "w", encoding="utf-8") as f:
        f.write(dummy_message)
    # For key size 64, we expect encryption to fail because data_area will be zero.
    result = run_command(cmd_encrypt, expect_error=True)
    # Check if ciphertext file was created (should not be)
    base, ext = os.path.splitext("message_small_key.txt")
    ciphertext_filename = f"{base}_cipher{ext}" if ext else f"message_small_key.txt_cipher"
    if os.path.exists(ciphertext_filename):
        print(f"ERROR: Ciphertext file '{ciphertext_filename}' was created unexpectedly.")
    else:
        print("Encryption failed as expected for key size 64.")

if __name__ == "__main__":
    main()
