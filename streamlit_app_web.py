"""
streamlit_app.py
----------------
A web application for demonstrating RSA cryptography using SageMath.

Usage:
    streamlit run streamlit_app.py --server.maxUploadSize=50

(Ensure server.maxUploadSize is set to the highest limit needed, e.g., 50MB for decryption.)

This Streamlit application provides a user-friendly graphical interface for a complete
RSA (Rivest-Shamir-Adleman) cryptographic workflow. It leverages backend SageMath
Python scripts (`rsa_keygenerator.py`, `rsa_encrypt.py`, `rsa_decrypt.py`) to
perform the core cryptographic operations.

The application allows users to:

1.  **Generate RSA Keys (Step 1):**
    *   Input: Desired bit length for the prime numbers (p and q).
    *   Action: Invokes `rsa_keygenerator.py` to generate a public/private key pair.
    *   Output: Provides download links for `public_key.csv` (containing e, n) and
              `private_key.csv` (containing d, n).

2.  **Encrypt File (Step 2):**
    *   Input: An arbitrary file to be encrypted (max 10MB) and the `public_key.csv` (max 10MB).
    *   Action: Invokes `rsa_encrypt.py`.
    *   Output: Provides a download link for the encrypted file.

3.  **Decrypt File (Step 3):**
    *   Input: An encrypted file (max 50MB) and the corresponding `private_key.csv` (max 10MB).
    *   Action: Invokes `rsa_decrypt.py`.
    *   Output: Provides a download link for the decrypted file.

4.  **Verify Decryption (Compare Files - Step 4):**
    *   Input: Two arbitrary files.
    *   Action: Performs a byte-by-byte comparison.
    *   Output: Displays success or failure.

The application maintains session-specific temporary directories.
"""

import streamlit as st
import subprocess
import os
import tempfile
import uuid
import base64
import shutil # Kept for potential future use

# --- Configuration ---
SAGE_EXECUTABLE = "sage" # Ensure 'sage' is in PATH
BASE_TEMP_DIR = os.path.join(tempfile.gettempdir(), "st_rsa_app_workspace")
APP_SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

KEYGEN_SCRIPT_NAME = "rsa_keygenerator.py"
ENCRYPT_SCRIPT_NAME = "rsa_encrypt.py"
DECRYPT_SCRIPT_NAME = "rsa_decrypt.py"

# --- File Upload Size Limits (in MB) ---
MAX_ENCRYPT_UPLOAD_FILE_MB = 10
MAX_KEY_FILE_UPLOAD_MB = 10
MAX_DECRYPT_UPLOAD_CIPHER_MB = 50

st.set_page_config(layout="wide", page_title="RSA Workflow with SageMath")

# --- Initialize Session State ---
if 'session_id' not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if 'key_gen_public_key_path' not in st.session_state:
    st.session_state.key_gen_public_key_path = None
if 'key_gen_private_key_path' not in st.session_state:
    st.session_state.key_gen_private_key_path = None
if 'encrypt_output_cipher_path' not in st.session_state:
    st.session_state.encrypt_output_cipher_path = None
if 'decrypt_output_plain_path' not in st.session_state:
    st.session_state.decrypt_output_plain_path = None

# --- Helper Functions ---
def get_session_dir():
    """Creates and returns the path to the current session's temporary directory."""
    path = os.path.join(BASE_TEMP_DIR, st.session_state.session_id)
    os.makedirs(path, exist_ok=True)
    return path

def run_sage_script(script_name, script_args, cwd, operation_name="SageMath Script"):
    """
    Runs a SageMath script as a subprocess and returns its success status, stdout, and stderr.
    """
    script_abs_path = os.path.join(APP_SCRIPT_DIR, script_name)
    cmd = [SAGE_EXECUTABLE, script_abs_path] + script_args

    display_cmd_args = [f"'{arg}'" if " " in arg else arg for arg in script_args]
    display_cmd_str = f"`{SAGE_EXECUTABLE} {script_abs_path} {' '.join(display_cmd_args)}`"
    st.info(f"Running {operation_name}: {display_cmd_str} (in directory: `{cwd}`)")

    try:
        process = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=360)
        stdout_clean = process.stdout.strip() if process.stdout else ""
        stderr_clean = process.stderr.strip() if process.stderr else ""

        if stdout_clean:
            pass
        if stderr_clean:
            st.warning(f"{operation_name} STDERR:\n```\n{stderr_clean}\n```")

        if process.returncode == 0:
            if "Error:" in stdout_clean or "Error:" in stderr_clean:
                 st.warning(f"{operation_name} completed with exit code 0, but an 'Error:' message was found in its output. Please review.")
            return True, stdout_clean, stderr_clean
        else:
            st.error(f"{operation_name} failed. Return code: {process.returncode}.")
            if not stderr_clean and stdout_clean :
                 st.info(f"Output from failed script ({operation_name}):\n```\n{stdout_clean}\n```")
            return False, stdout_clean, stderr_clean

    except subprocess.TimeoutExpired:
        st.error(f"{operation_name} timed out after 6 minutes.")
        return False, "", "ProcessTimedOut"
    except FileNotFoundError:
        errmsg = (f"SAGE EXECUTABLE ('{SAGE_EXECUTABLE}') or SCRIPT ('{script_abs_path}') NOT FOUND. "
                  f"Ensure SageMath is installed, '{SAGE_EXECUTABLE}' is in your system's PATH, "
                  f"and the script exists at the expected location.")
        st.error(errmsg)
        return False, "", "SageOrScriptNotFound"
    except Exception as e:
        st.error(f"An unexpected Python error occurred while preparing to run or running {operation_name}: {str(e)}")
        return False, "", str(e)

# --- Sidebar Content ---
logo_path = os.path.join(APP_SCRIPT_DIR, "univ-logo.png")
if os.path.exists(logo_path):
    try:
        with open(logo_path, "rb") as f:
            img_bytes = f.read()
        img_b64 = base64.b64encode(img_bytes).decode()
        logo_html = f"""
            <div style="display: flex; justify-content: center; margin-bottom: 20px;">
                <img src="data:image/png;base64,{img_b64}" alt="University Logo" width="100">
            </div>"""
        st.sidebar.markdown(logo_html, unsafe_allow_html=True)
    except Exception as e:
        st.sidebar.warning(f"Could not display logo: {e}")
else:
    st.sidebar.warning("University logo ('univ-logo.png') not found in the application directory.")

st.sidebar.title("RSA Cryptography Tool")
st.sidebar.markdown("### Final Year Project (Group 27)")
st.sidebar.markdown("#### Bachelor of Engineering in Information Technology")
st.sidebar.markdown("Jadavpur University, Salt Lake Campus")
st.sidebar.markdown("Session: 2024-2025")
st.sidebar.markdown("---")
st.sidebar.markdown("##### By:")
st.sidebar.markdown("- **Sayan Das** (302211001006)")
st.sidebar.markdown("- **Saugata Ghosh** (302211001007)")
st.sidebar.markdown("- **Suvajit Sadhukhan** (302211001005)")
st.sidebar.markdown("- **Subhankar Das** (002111001147)")
st.sidebar.markdown("---")

with st.sidebar.expander("About This Application", expanded=False):
    st.markdown(f"""
    This web application demonstrates a complete RSA (Rivest-Shamir-Adleman) cryptographic workflow.
    It allows you to:
    1.  **Generate** RSA public and private key pairs.
    2.  **Encrypt** arbitrary files (up to {MAX_ENCRYPT_UPLOAD_FILE_MB}MB) using a public key.
    3.  **Decrypt** ciphertexts (up to {MAX_DECRYPT_UPLOAD_CIPHER_MB}MB) using the corresponding private key.
    4.  **Compare** files byte-by-byte (e.g., to verify decryption).

    Key files (`public_key.csv`, `private_key.csv`) are limited to {MAX_KEY_FILE_UPLOAD_MB}MB.
    All cryptographic operations are performed using SageMath scripts executed by this Streamlit application.
    Temporary files generated during operations are stored in a session-specific directory.
    This project is part of a Final Year Project for Bachelor of Engineering in Information Technology.
    """)

with st.sidebar.expander("How to Use", expanded=False):
    st.markdown(f"""
    Follow these steps through the application:

    **Step 1: Generate RSA Keys**
    *   Enter a "Bit Length" for the prime numbers (p and q). Common values are 256, 512, 1024. Larger bit lengths offer stronger security but result in slower operations.
    *   Click "Generate Keys".
    *   Download `public_key.csv` and `private_key.csv`. **Keep `private_key.csv` secure!**

    **Step 2: Encrypt File**
    *   Upload any file you want to encrypt (Placeholder text shows max: {MAX_ENCRYPT_UPLOAD_FILE_MB}MB).
    *   Upload the `public_key.csv` generated in Step 1 (Placeholder text shows max: {MAX_KEY_FILE_UPLOAD_MB}MB).
    *   Click "Encrypt File".
    *   Download the encrypted file.

    **Step 3: Decrypt File**
    *   Upload the encrypted file from Step 2 (Placeholder text shows max: {MAX_DECRYPT_UPLOAD_CIPHER_MB}MB).
    *   Upload the corresponding `private_key.csv` (Placeholder text shows max: {MAX_KEY_FILE_UPLOAD_MB}MB).
    *   Click "Decrypt File".
    *   Download the decrypted file.

    **Step 4: Compare Files**
    *   Upload two files. Click "Compare Files".
    """)

# --- Main Application UI ---
st.title("RSA File Encryption & Decryption Workflow with SageMath")
session_temp_dir = get_session_dir()

# --- Custom CSS Injection for File Uploader Placeholder Text ---
# This CSS targets the internal structure of Streamlit's file_uploader.
# It might break with future Streamlit updates if the HTML structure changes.
# You may need to inspect the element using browser dev tools to adjust selectors if it breaks.
st.markdown(f"""
<style>
/* Target the div that contains the 'Limit XMB per file' text */
/* This selector is based on common Streamlit HTML structure for file uploader */
/* It targets the last div child within the main dropzone text container */
[data-testid="stFileUploadDropzone"] > div > div:last-child {{
    font-size: 0 !important; /* Hide original text by making font size 0 */
    line-height: 0; /* Ensure it takes no vertical space */
    padding: 0 !important;
    margin: 0 !important;
}}
[data-testid="stFileUploadDropzone"] > div > div:last-child::before {{
    font-size: 14px; /* Restore font size for new text (Streamlit's default is 14px) */
    color: #808498; /* Streamlit's default secondary text color */
    display: block; /* Ensure it takes up space */
    line-height: normal; /* Restore line height */
    padding-top: 5px; /* Add some spacing if needed */
}}

/* Specific limits based on wrapper class */
.uploader-limit-{MAX_ENCRYPT_UPLOAD_FILE_MB}mb [data-testid="stFileUploadDropzone"] > div > div:last-child::before {{
    content: 'Limit {MAX_ENCRYPT_UPLOAD_FILE_MB}MB per file';
}}
.uploader-limit-{MAX_KEY_FILE_UPLOAD_MB}mb-csv [data-testid="stFileUploadDropzone"] > div > div:last-child::before {{
    content: 'Limit {MAX_KEY_FILE_UPLOAD_MB}MB per file • CSV';
}}
.uploader-limit-{MAX_DECRYPT_UPLOAD_CIPHER_MB}mb [data-testid="stFileUploadDropzone"] > div > div:last-child::before {{
    content: 'Limit {MAX_DECRYPT_UPLOAD_CIPHER_MB}MB per file';
}}
</style>
""", unsafe_allow_html=True)


# --- 1. Key Generation ---
with st.expander("Step 1: Generate RSA Keys", expanded=True):
    bit_length_keygen = st.number_input(
        "Enter Bit Length for Primes (e.g., 512, 1024, 2048):",
        min_value=128, max_value=4096, value=512, step=128,
        key="keygen_bits",
        help="This bit length is for p and q. The modulus n will be roughly twice this length."
    )

    cols_keygen_button_outer = st.columns([1,1.5,1])
    with cols_keygen_button_outer[1]:
        if st.button("Generate Keys", key="keygen_button", type="primary", use_container_width=True):
            keygen_op_dir = os.path.join(session_temp_dir, "key_generation")
            os.makedirs(keygen_op_dir, exist_ok=True)
            st.session_state.key_gen_public_key_path = None
            st.session_state.key_gen_private_key_path = None
            success, stdout, _ = run_sage_script(
                KEYGEN_SCRIPT_NAME, [str(bit_length_keygen)], cwd=keygen_op_dir, operation_name="RSA Key Generation"
            )
            if success and "Keys generated successfully." in stdout:
                pub_key_path = os.path.join(keygen_op_dir, "public_key.csv")
                priv_key_path = os.path.join(keygen_op_dir, "private_key.csv")
                if os.path.exists(pub_key_path) and os.path.exists(priv_key_path):
                    st.session_state.key_gen_public_key_path = pub_key_path
                    st.session_state.key_gen_private_key_path = priv_key_path
                    st.success("RSA keys generated successfully!")
                else:
                    st.error("Key files not found after script execution. Check script output for details.")
            elif success:
                 st.warning("Key generation script finished, but the expected success message was not found.")

    dl_col1_outer, dl_col2_outer = st.columns(2)
    with dl_col1_outer:
        dl_subcol1_center = st.columns([1,2,1])[1]
        if st.session_state.get('key_gen_public_key_path') and os.path.exists(st.session_state.key_gen_public_key_path):
            with open(st.session_state.key_gen_public_key_path, "rb") as fp:
                dl_subcol1_center.download_button(
                    label="Download Public Key (public_key.csv)", data=fp, file_name="public_key.csv",
                    mime="text/csv", key="download_pub_key_button", type="secondary", use_container_width=True
                )
    with dl_col2_outer:
        dl_subcol2_center = st.columns([1,2,1])[1]
        if st.session_state.get('key_gen_private_key_path') and os.path.exists(st.session_state.key_gen_private_key_path):
            with open(st.session_state.key_gen_private_key_path, "rb") as fp:
                dl_subcol2_center.download_button(
                    label="Download Private Key (private_key.csv)", data=fp, file_name="private_key.csv",
                    mime="text/csv", key="download_priv_key_button", type="secondary", use_container_width=True
                )

# --- 2. Encryption ---
with st.expander("Step 2: Encrypt File"):
    st.markdown(f'<div class="uploader-limit-{MAX_ENCRYPT_UPLOAD_FILE_MB}mb">', unsafe_allow_html=True)
    uploaded_file_encrypt = st.file_uploader(
        "Upload File to Encrypt (any type under 10MB):",
        type=None,
        key="encrypt_file_upload",
        help=f"Actual limit: {MAX_ENCRYPT_UPLOAD_FILE_MB}MB. Ensure Streamlit server `maxUploadSize` is sufficient."
    )
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown(f'<div class="uploader-limit-{MAX_KEY_FILE_UPLOAD_MB}mb-csv">', unsafe_allow_html=True)
    uploaded_public_key_encrypt = st.file_uploader(
        "Upload Public Key File (`public_key.csv`):",
        type=['csv'],
        key="encrypt_pubkey_upload",
        help=f"Actual limit: {MAX_KEY_FILE_UPLOAD_MB}MB. Ensure Streamlit server `maxUploadSize` is sufficient."
    )
    st.markdown('</div>', unsafe_allow_html=True)

    cols_encrypt_button_outer = st.columns([1,1.5,1])
    with cols_encrypt_button_outer[1]:
        if st.button("Encrypt File", key="encrypt_button", type="primary", use_container_width=True):
            if uploaded_file_encrypt and uploaded_public_key_encrypt:
                if uploaded_file_encrypt.size > MAX_ENCRYPT_UPLOAD_FILE_MB * 1024 * 1024:
                    st.error(f"File to encrypt exceeds the {MAX_ENCRYPT_UPLOAD_FILE_MB}MB limit. Please upload a smaller file.")
                elif uploaded_public_key_encrypt.size > MAX_KEY_FILE_UPLOAD_MB * 1024 * 1024:
                    st.error(f"Public key file exceeds the {MAX_KEY_FILE_UPLOAD_MB}MB limit. Please upload a smaller key file.")
                else:
                    encrypt_op_dir = os.path.join(session_temp_dir, "encryption")
                    os.makedirs(encrypt_op_dir, exist_ok=True)
                    st.session_state.encrypt_output_cipher_path = None
                    script_input_filename = uploaded_file_encrypt.name
                    temp_input_file_path = os.path.join(encrypt_op_dir, script_input_filename)
                    with open(temp_input_file_path, "wb") as f:
                        f.write(uploaded_file_encrypt.getvalue())
                    with open(os.path.join(encrypt_op_dir, "public_key_for_encrypt.csv"), "wb") as f:
                        f.write(uploaded_public_key_encrypt.getvalue())
                    success, stdout, _ = run_sage_script(
                        ENCRYPT_SCRIPT_NAME,
                        [script_input_filename, "public_key_for_encrypt.csv"],
                        cwd=encrypt_op_dir,
                        operation_name="RSA File Encryption"
                    )
                    if success and "Encryption complete." in stdout:
                        cipher_filename_from_log = next((line.split("Encrypted file:",1)[1].strip() for line in stdout.splitlines() if "Encrypted file:" in line), None)
                        if cipher_filename_from_log:
                            cipher_file_path = os.path.join(encrypt_op_dir, cipher_filename_from_log)
                            if os.path.exists(cipher_file_path):
                                st.session_state.encrypt_output_cipher_path = cipher_file_path
                                st.success(f"File encrypted successfully! Ciphertext file: `{os.path.basename(cipher_file_path)}`")
                            else:
                                st.error(f"Ciphertext file '{cipher_filename_from_log}' not found.")
                        else:
                            st.error("Encryption script completed, but ciphertext filename not found in output.")
                    elif success:
                         st.warning("Encryption script finished, but expected success message not found.")
            else:
                st.warning("Please upload both a file to encrypt and a public key file.")

    cols_enc_download_outer = st.columns([1,1.5,1])
    with cols_enc_download_outer[1]:
        if st.session_state.get('encrypt_output_cipher_path') and os.path.exists(st.session_state.encrypt_output_cipher_path):
            download_fn_enc = os.path.basename(st.session_state.encrypt_output_cipher_path)
            with open(st.session_state.encrypt_output_cipher_path, "rb") as fp:
                st.download_button(
                    label=f"Download Encrypted File", data=fp, file_name=download_fn_enc,
                    mime="text/plain", key="download_cipher_button", type="secondary", use_container_width=True
                )

# --- 3. Decryption ---
with st.expander("Step 3: Decrypt File"):
    st.markdown(f'<div class="uploader-limit-{MAX_DECRYPT_UPLOAD_CIPHER_MB}mb">', unsafe_allow_html=True)
    uploaded_cipher_decrypt = st.file_uploader(
        "Upload Encrypted File (e.g., `filename_cipher.ext`):",
        type=None, key="decrypt_cipher_upload",
        help=f"Actual limit: {MAX_DECRYPT_UPLOAD_CIPHER_MB}MB. Ensure Streamlit server `maxUploadSize` is sufficient."
    )
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown(f'<div class="uploader-limit-{MAX_KEY_FILE_UPLOAD_MB}mb-csv">', unsafe_allow_html=True)
    uploaded_private_key_decrypt = st.file_uploader(
        "Upload Private Key File (`private_key.csv`):",
        type=['csv'], key="decrypt_privkey_upload",
        help=f"Actual limit: {MAX_KEY_FILE_UPLOAD_MB}MB. Ensure Streamlit server `maxUploadSize` is sufficient."
    )
    st.markdown('</div>', unsafe_allow_html=True)

    cols_decrypt_button_outer = st.columns([1,1.5,1])
    with cols_decrypt_button_outer[1]:
        if st.button("Decrypt File", key="decrypt_button", type="primary", use_container_width=True):
            if uploaded_cipher_decrypt and uploaded_private_key_decrypt:
                if uploaded_cipher_decrypt.size > MAX_DECRYPT_UPLOAD_CIPHER_MB * 1024 * 1024:
                    st.error(f"Encrypted file exceeds the {MAX_DECRYPT_UPLOAD_CIPHER_MB}MB limit.")
                elif uploaded_private_key_decrypt.size > MAX_KEY_FILE_UPLOAD_MB * 1024 * 1024:
                    st.error(f"Private key file exceeds the {MAX_KEY_FILE_UPLOAD_MB}MB limit.")
                else:
                    decrypt_op_dir = os.path.join(session_temp_dir, "decryption")
                    os.makedirs(decrypt_op_dir, exist_ok=True)
                    st.session_state.decrypt_output_plain_path = None
                    script_input_cipher_name = uploaded_cipher_decrypt.name
                    temp_cipher_file_path = os.path.join(decrypt_op_dir, script_input_cipher_name)
                    with open(temp_cipher_file_path, "wb") as f:
                        f.write(uploaded_cipher_decrypt.getvalue())
                    with open(os.path.join(decrypt_op_dir, "private_key_for_decrypt.csv"), "wb") as f:
                        f.write(uploaded_private_key_decrypt.getvalue())
                    success, stdout, _ = run_sage_script(
                        DECRYPT_SCRIPT_NAME,
                        [script_input_cipher_name, "private_key_for_decrypt.csv"],
                        cwd=decrypt_op_dir, operation_name="RSA File Decryption"
                    )
                    if success and "Decryption complete." in stdout:
                        decrypted_filename_from_log = next((line.split("Decrypted file:",1)[1].strip() for line in stdout.splitlines() if "Decrypted file:" in line), None)
                        if decrypted_filename_from_log:
                            decrypted_file_path = os.path.join(decrypt_op_dir, decrypted_filename_from_log)
                            if os.path.exists(decrypted_file_path):
                                st.session_state.decrypt_output_plain_path = decrypted_file_path
                                st.success(f"File decrypted successfully! Decrypted file: `{os.path.basename(decrypted_file_path)}`")
                            else:
                                st.error(f"Decrypted file '{decrypted_filename_from_log}' not found.")
                        else:
                            st.error("Decryption script completed, but decrypted filename not found in output.")
                    elif success:
                        st.warning("Decryption script finished, but expected success message not found.")
            else:
                st.warning("Please upload both an encrypted file and a private key file.")

    cols_dec_download_outer = st.columns([1,1.5,1])
    with cols_dec_download_outer[1]:
        if st.session_state.get('decrypt_output_plain_path') and os.path.exists(st.session_state.decrypt_output_plain_path):
            download_fn_dec = os.path.basename(st.session_state.decrypt_output_plain_path)
            with open(st.session_state.decrypt_output_plain_path, "rb") as fp:
                st.download_button(
                    label=f"Download Decrypted File", data=fp, file_name=download_fn_dec,
                    mime="application/octet-stream", key="download_decrypted_button", type="secondary", use_container_width=True
                )

# --- 4. Verify Decryption (Compare Files) ---
with st.expander("Step 4: Verify Decryption (Compare Files)"):
    st.write("Upload two files to compare their content. Previews shown if possible.")
    # Note: CSS for placeholder text is not applied to these general comparison uploaders by default.
    # If specific limits were desired here, similar CSS wrapping could be done.
    max_compare_size_info = max(MAX_ENCRYPT_UPLOAD_FILE_MB, MAX_DECRYPT_UPLOAD_CIPHER_MB, MAX_KEY_FILE_UPLOAD_MB)


    col_upload1, col_upload2 = st.columns(2)
    with col_upload1:
        file1_compare = st.file_uploader("Upload First File (e.g., Original):", type=None, key="compare_file1_upload_bin_v3", help=f"Max size guided by server config (e.g., up to {max_compare_size_info}MB or your `server.maxUploadSize` setting).")
    with col_upload2:
        file2_compare = st.file_uploader("Upload Second File (e.g., Decrypted):", type=None, key="compare_file2_upload_bin_v3", help=f"Max size guided by server config (e.g., up to {max_compare_size_info}MB or your `server.maxUploadSize` setting).")

    cols_compare_button_layout = st.columns([1,1.5,1])
    with cols_compare_button_layout[1]:
        compare_button_pressed = st.button("Compare Files & Show Previews", key="compare_files_button_bin_v3", type="primary", use_container_width=True)

    if compare_button_pressed:
        if file1_compare is not None and file2_compare is not None:
            bytes1 = file1_compare.getvalue()
            bytes2 = file2_compare.getvalue()
            if bytes1 == bytes2:
                st.success(f"✅ SUCCESS: Content of `{file1_compare.name}` and `{file2_compare.name}` is identical.")
            else:
                st.error(f"❌ FAILURE: Content of `{file1_compare.name}` and `{file2_compare.name}` differs.")
            st.markdown("---")
            st.subheader("File Previews:")
            preview_col1, preview_col2 = st.columns(2)
            def display_preview(column, uploaded_file, file_bytes, file_label="File"):
                with column:
                    st.markdown(f"**Preview of: `{uploaded_file.name}`**")
                    file_type = uploaded_file.type
                    preview_rendered = False
                    if file_type:
                        if file_type.startswith("image/"):
                            try:
                                column.image(file_bytes, use_container_width=True)
                                preview_rendered = True
                            except Exception: pass
                        elif file_type == "text/plain":
                            try:
                                text_content = ""
                                for encoding in ['utf-8', 'ascii', 'latin-1']:
                                    try:
                                        text_content = file_bytes.decode(encoding)
                                        break
                                    except UnicodeDecodeError: continue
                                if text_content:
                                    unique_key = f"text_preview_{uploaded_file.file_id}_{file_label.lower().replace(' ', '_')}"
                                    column.text_area(f"Text Content", value=text_content, height=200, disabled=True, key=unique_key)
                                    preview_rendered = True
                            except Exception: pass
                    if not preview_rendered:
                        column.info(f"Preview not available for this file type (`{file_type if file_type else 'Unknown'}`).")
                        column.caption(f"Filename: `{uploaded_file.name}`, Size: {len(file_bytes):,} bytes")
            display_preview(preview_col1, file1_compare, bytes1, "File1")
            display_preview(preview_col2, file2_compare, bytes2, "File2")
        else:
            st.warning("Please upload both files for comparison.")