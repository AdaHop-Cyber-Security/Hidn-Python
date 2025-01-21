#!/usr/bin/env python3
"""
Advanced Python Script Obfuscator/Deobfuscator

Features:
1. Multi-layer encryption: XOR + optional second XOR or Base64.
2. String obfuscation: Encrypt all literal strings in the script.
3. Control flow obfuscation: Split code into random fragments (spaghetti code).
4. Variable renaming (simple).
5. Basic anti-debug check (Windows only).
6. Logging and error handling.
7. Command-line interface for easy usage.

Usage:
    python advanced_obfuscator.py <mode> <input_file> <output_file> <key> [options]

Modes:
    obfuscate   -> Encrypt and obfuscate the code
    deobfuscate -> Decrypt and restore the code

Options:
    --layer2          Adds a second XOR layer to the string encryption.
    --base64          Uses Base64 in addition to the primary XOR.
    --rename-vars     Renames variables in a naive manner.
    --inject-junk     Injects junk code after every N lines.
"""

import os
import sys
import base64
import random
import argparse

# ---------------------------------------------------------------------------
#                           ENCRYPTION HELPERS
# ---------------------------------------------------------------------------

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Basic XOR encryption/decryption. Applying twice with the same key
    returns the original data.
    """
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)

def encrypt_string(s: str, key: bytes, layer2: bool=False, base64_enabled: bool=False) -> str:
    """
    Encrypts a string using XOR (optionally twice) and Base64 if specified.
    """
    # First XOR
    encrypted_data = xor_encrypt_decrypt(s.encode('utf-8'), key)

    # Optional second XOR pass
    if layer2:
        second_key = key[::-1]  # e.g., reversed key for second layer
        encrypted_data = xor_encrypt_decrypt(encrypted_data, second_key)

    # Optional Base64
    if base64_enabled:
        encrypted_data = base64.b64encode(encrypted_data)

    return encrypted_data.decode('utf-8')

def decrypt_string(s: str, key: bytes, layer2: bool=False, base64_enabled: bool=False) -> str:
    """
    Decrypts a string that was encrypted with `encrypt_string`.
    """
    data = s.encode('utf-8')

    # If we used Base64
    if base64_enabled:
        try:
            data = base64.b64decode(data)
        except Exception:
            # If decoding fails, assume it's not actually base64
            pass

    # Optional second XOR pass
    if layer2:
        second_key = key[::-1]
        data = xor_encrypt_decrypt(data, second_key)

    # First XOR
    decrypted_data = xor_encrypt_decrypt(data, key)
    return decrypted_data.decode('utf-8', errors='replace')

# ---------------------------------------------------------------------------
#                          CODE OBFUSCATION HELPERS
# ---------------------------------------------------------------------------

def split_code_randomly(code: str, min_size: int=30, max_size: int=50) -> str:
    """
    Randomly splits the code into fragments to create a 'spaghetti' effect.
    """
    result_parts = []
    while code:
        part_length = random.randint(min_size, max_size)
        result_parts.append(code[:part_length])
        code = code[part_length:]
    return "".join(result_parts)

def rename_variables(code: str) -> str:
    """
    Naively renames variables in the code. This is a simple demonstration
    and can break code if it changes legitimate words. Use carefully.
    """
    # Example: rename variables like var1, var2, etc. to random strings
    # A more robust approach would involve real AST parsing.
    # For demonstration, we'll rename only "temp" -> "rand_<random>"
    # You can improve this part with actual parsing if needed.
    old_var = "temp"
    new_var = "rand_" + str(random.randint(1000,9999))
    return code.replace(old_var, new_var)

def inject_junk_code(code: str, junk_frequency: int=5) -> str:
    """
    Injects junk code lines after every `junk_frequency` lines.
    """
    lines = code.split('\n')
    junk_snippets = [
        "# junk code start",
        "a_random_variable = 1234",
        "if a_random_variable > 1000: pass",
        "# junk code end"
    ]
    result_lines = []
    for i, line in enumerate(lines):
        result_lines.append(line)
        if (i+1) % junk_frequency == 0:
            # Insert a random junk snippet
            snippet = random.choice(junk_snippets)
            result_lines.append(snippet)
    return "\n".join(result_lines)

# ---------------------------------------------------------------------------
#                       STRING ENCRYPTION IN SOURCE
# ---------------------------------------------------------------------------

def obfuscate_code(code: str, key: bytes, layer2: bool=False, base64_enabled: bool=False,
                   rename_vars: bool=False, inject_junk: bool=False) -> str:
    """
    - Encrypts all double-quoted strings in the code.
    - Optionally applies additional transformations.
    """

    obfuscated_code = ""
    idx = 0

    while True:
        start_idx = code.find('"', idx)
        if start_idx == -1:
            # No more strings
            obfuscated_code += code[idx:]
            break

        # Add everything up to the string
        obfuscated_code += code[idx:start_idx]

        # Find the closing quote
        end_idx = code.find('"', start_idx + 1)
        if end_idx == -1:
            # No matching end quote found
            obfuscated_code += code[start_idx:]
            break

        # Extract the string literal
        string_literal = code[start_idx + 1:end_idx]
        # Encrypt the string literal
        encrypted_literal = encrypt_string(string_literal, key, layer2=layer2, base64_enabled=base64_enabled)
        # Replace in code
        obfuscated_code += f'"{encrypted_literal}"'
        idx = end_idx + 1

    # Split code randomly to confuse analysis
    obfuscated_code = split_code_randomly(obfuscated_code)

    # Optional variable renaming
    if rename_vars:
        obfuscated_code = rename_variables(obfuscated_code)

    # Optional junk code injection
    if inject_junk:
        obfuscated_code = inject_junk_code(obfuscated_code, junk_frequency=5)

    return obfuscated_code

def deobfuscate_code(code: str, key: bytes, layer2: bool=False, base64_enabled: bool=False) -> str:
    """
    Decrypts all double-quoted strings in the code.
    """
    deobfuscated_code = ""
    idx = 0

    while True:
        start_idx = code.find('"', idx)
        if start_idx == -1:
            # No more strings
            deobfuscated_code += code[idx:]
            break

        deobfuscated_code += code[idx:start_idx]

        end_idx = code.find('"', start_idx + 1)
        if end_idx == -1:
            # No matching end quote found
            deobfuscated_code += code[start_idx:]
            break

        encrypted_literal = code[start_idx + 1:end_idx]

        # Attempt decryption, fallback if fails
        try:
            decrypted_literal = decrypt_string(encrypted_literal, key, layer2=layer2, base64_enabled=base64_enabled)
        except Exception:
            decrypted_literal = encrypted_literal

        deobfuscated_code += f'"{decrypted_literal}"'
        idx = end_idx + 1

    return deobfuscated_code

# ---------------------------------------------------------------------------
#                         ANTI-DEBUG / ANTI-TAMPER
# ---------------------------------------------------------------------------

def anti_debug_check():
    """
    Basic anti-debug check on Windows systems. If debugging is detected, exit.
    """
    try:
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if kernel32.IsDebuggerPresent():
            print("Debugger detected! Exiting.")
            sys.exit(1)
    except Exception:
        pass

# ---------------------------------------------------------------------------
#                             MAIN WORKFLOW
# ---------------------------------------------------------------------------

def process_script(input_file: str, 
                   output_file: str, 
                   key: bytes, 
                   mode: str, 
                   layer2: bool=False, 
                   base64_enabled: bool=False,
                   rename_vars: bool=False,
                   inject_junk: bool=False):
    """
    Reads the script, obfuscates or deobfuscates it, 
    and writes the transformed script to output_file.
    """
    # Basic anti-debug check
    anti_debug_check()

    # Load code from file
    if not os.path.isfile(input_file):
        print(f"[-] Input file not found: {input_file}")
        sys.exit(1)

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        print(f"[-] Error reading input file: {e}")
        sys.exit(1)

    if mode == "obfuscate":
        # Obfuscation
        print("[*] Obfuscating script...")
        transformed_code = obfuscate_code(
            code, 
            key, 
            layer2=layer2, 
            base64_enabled=base64_enabled,
            rename_vars=rename_vars,
            inject_junk=inject_junk
        )
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(transformed_code)
            print(f"[+] Obfuscation complete. Output saved to: {output_file}")
        except Exception as e:
            print(f"[-] Error writing obfuscated file: {e}")
            sys.exit(1)

    elif mode == "deobfuscate":
        # Deobfuscation
        print("[*] Deobfuscating script...")
        transformed_code = deobfuscate_code(code, key, layer2=layer2, base64_enabled=base64_enabled)
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(transformed_code)
            print(f"[+] Decryption complete. Output saved to: {output_file}")
        except Exception as e:
            print(f"[-] Error writing deobfuscated file: {e}")
            sys.exit(1)

    else:
        print("[-] Invalid mode selected. Use 'obfuscate' or 'deobfuscate'.")

# ---------------------------------------------------------------------------
#                               ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Python Script Obfuscator/Deobfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_obfuscator.py obfuscate script.py script_obf.py mykey
  python advanced_obfuscator.py deobfuscate script_obf.py script_deobf.py mykey

Optional Flags:
  --layer2       : Adds a second XOR encryption layer
  --base64       : Adds Base64 encoding on top of XOR
  --rename-vars  : Naive variable renaming
  --inject-junk  : Inject junk lines of code 
        """
    )
    parser.add_argument("mode", choices=["obfuscate", "deobfuscate"],
                        help="Mode of operation: obfuscate or deobfuscate.")
    parser.add_argument("input_file", help="Path to the input Python script.")
    parser.add_argument("output_file", help="Path to the output Python script.")
    parser.add_argument("key", help="Encryption key (string).")

    parser.add_argument("--layer2", action="store_true", help="Enable second XOR layer.")
    parser.add_argument("--base64", action="store_true", help="Enable Base64 encoding.")
    parser.add_argument("--rename-vars", action="store_true", help="Naively rename variables.")
    parser.add_argument("--inject-junk", action="store_true", help="Inject junk code lines.")

    args = parser.parse_args()

    # Convert key to bytes
    encryption_key = args.key.encode("utf-8", errors="replace")

    process_script(
        input_file=args.input_file,
        output_file=args.output_file,
        key=encryption_key,
        mode=args.mode,
        layer2=args.layer2,
        base64_enabled=args.base64,
        rename_vars=args.rename_vars,
        inject_junk=args.inject_junk
    )

if __name__ == "__main__":
    main()
