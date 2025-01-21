# Hidn-Python

Python script that includes both encryption and decryption functionalities. This version allows you to obfuscate and deobfuscate a Python script by encrypting and decrypting strings within the code
DO NOT UPLOAD TO VIRUSTOTAL.COM OR EQUIVALENT!

---

Usage:

1. Obfuscating a Script

To obfuscate a Python script, run the following command:
python obfuscator.py obfuscate input.py obfuscated.py my_secret_key

---    

2. Deobfuscating a Script

To deobfuscate an obfuscated script, run:

python obfuscator.py deobfuscate obfuscated.py decrypted.py my_secret_key

---

Explanation of the Changes

    Encryption and Decryption:
        Added string_decrypt() function to reverse the encryption process.
        Base64 and XOR encryption used for string protection.

    Command-line Arguments:
        The script can now take input/output file paths and encryption keys as command-line arguments.
        User can specify whether they want to obfuscate or deobfuscate.

    Anti-Debugging Check:
        Added a function that exits the script if it detects debugging.

    File Handling:
        Reads the script content from the specified input file and writes to the output file.

---        

Sample Input Python Script (input.py)

print("Hello, world!")
name = "John Doe"
age = 30
print(f"Name: {name}, Age: {age}")

Obfuscated Output (obfuscated.py)

print("U1RGQkdGSA==")
name = "UldXWkZJQQ=="
age = 30
print(f"Name: {name}, Age: {age}")

Decrypted Output (decrypted.py)


