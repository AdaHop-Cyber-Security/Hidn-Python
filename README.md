# Hidn-Python

How to Use

    Install Requirements (if any):
        None strictly needed beyond standard Python libraries.

    Run Obfuscation:

python advanced_obfuscator.py obfuscate path/to/script.py path/to/obf_script.py "MySecretKey" [--layer2] [--base64] [--rename-vars] [--inject-junk]

Example:

python advanced_obfuscator.py obfuscate script.py script_obf.py MyKey --layer2 --base64 --rename-vars --inject-junk

This will:

    XOR-encrypt all string literals.
    Add a second XOR pass (--layer2).
    Base64-encode after XOR (--base64).
    Naively rename variables (--rename-vars).
    Inject junk lines after every 5 lines (--inject-junk).

Run Deobfuscation:

python advanced_obfuscator.py deobfuscate path/to/obf_script.py path/to/deobf_script.py "MySecretKey" [--layer2] [--base64]

Example:

    python advanced_obfuscator.py deobfuscate script_obf.py script_deobf.py MyKey --layer2 --base64

    Must use the same options (--layer2, --base64) and key you used during obfuscation to properly restore the original strings.

    Check the Output
        The obfuscated file (script_obf.py) will be significantly different and harder to read.
        The deobfuscated file (script_deobf.py) should resemble the original code’s functionality, with the encrypted strings restored.

Important Notes:

    Variable Renaming: The included renaming logic is very naive and can break your code if it inadvertently renames parts of strings or function names. A robust solution would parse the code’s Abstract Syntax Tree (AST).
    Junk Code Injection: This example only shows a trivial demonstration. Real junk code insertion would likely require deeper code analysis to avoid breaking functionality.
    Security: Relying solely on string encryption and code obfuscation is never a complete security solution. Always use proper security and encryption practices for sensitive data.
    Cross-Platform: The anti_debug_check function is basic and primarily relevant on Windows. On other systems, it typically does nothing.

With this script, you have a more comprehensive, layered approach to obfuscating your Python scripts. Keep in mind that determined reverse-engineers can still work through these layers if they are motivated, but it certainly raises the complexity of analyzing your code.
