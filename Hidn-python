import base64
import random
import argparse

def xor_encrypt_decrypt(data, key):
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)

def string_encrypt(s, key):
    encrypted_data = xor_encrypt_decrypt(s.encode(), key)
    return base64.b64encode(encrypted_data).decode()

def string_decrypt(s, key):
    decoded_data = base64.b64decode(s.encode())
    return xor_encrypt_decrypt(decoded_data, key).decode()

def split_code(code):
    code_parts = []
    while code:
        part_length = random.randint(30, 50)
        code_parts.append(code[:part_length])
        code = code[part_length:]
    return code_parts

def obfuscate_code(code, key):
    encrypted_strings = {}
    
    # Encrypt strings in the code
    encrypted_code = ""
    while True:
        start_idx = code.find('"')
        if start_idx == -1:
            encrypted_code += code
            break
        
        end_idx = code.find('"', start_idx + 1)
        if end_idx == -1:
            encrypted_code += code
            break

        string_to_encrypt = code[start_idx + 1:end_idx]
        encrypted_string = string_encrypt(string_to_encrypt, key)
        encrypted_strings[string_to_encrypt] = encrypted_string
        encrypted_code += code[:start_idx] + f'"{encrypted_string}"'
        code = code[end_idx + 1:]

    return encrypted_code, encrypted_strings

def deobfuscate_code(code, key):
    decrypted_code = ""

    while True:
        start_idx = code.find('"')
        if start_idx == -1:
            decrypted_code += code
            break

        end_idx = code.find('"', start_idx + 1)
        if end_idx == -1:
            decrypted_code += code
            break

        encrypted_string = code[start_idx + 1:end_idx]
        try:
            decrypted_string = string_decrypt(encrypted_string, key)
        except:
            decrypted_string = encrypted_string  # In case decryption fails, leave it as is
        
        decrypted_code += code[:start_idx] + f'"{decrypted_string}"'
        code = code[end_idx + 1:]

    return decrypted_code

def anti_debug_check():
    try:
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32')
        is_debugged = kernel32.IsDebuggerPresent()
        if is_debugged:
            exit()
    except:
        pass

def process_script(input_file, output_file, key, mode):
    with open(input_file, "r") as file:
        code = file.read()

    if mode == "obfuscate":
        encrypted_code, encrypted_strings = obfuscate_code(code, key)
        obfuscated_code_parts = split_code(encrypted_code)
        
        with open(output_file, "w") as file:
            file.write("".join(obfuscated_code_parts))
        
        with open("encrypted_strings.txt", "w") as file:
            for original_string, encrypted_string in encrypted_strings.items():
                file.write(f"{original_string} => {encrypted_string}\n")

        print(f"Obfuscation complete. Output saved to {output_file}")
    elif mode == "deobfuscate":
        decrypted_code = deobfuscate_code(code, key)
        with open(output_file, "w") as file:
            file.write(decrypted_code)
        
        print(f"Decryption complete. Output saved to {output_file}")
    else:
        print("Invalid mode selected. Use 'obfuscate' or 'deobfuscate'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Script Obfuscator and Deobfuscator")
    parser.add_argument("mode", choices=["obfuscate", "deobfuscate"], help="Choose to obfuscate or deobfuscate the script.")
    parser.add_argument("input_file", help="Path to the input Python script.")
    parser.add_argument("output_file", help="Path to the output Python script.")
    parser.add_argument("key", help="Encryption key for obfuscation/deobfuscation.")

    args = parser.parse_args()

    # Convert key to bytes
    encryption_key = args.key.encode()

    process_script(args.input_file, args.output_file, encryption_key, args.mode)
