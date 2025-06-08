#!/usr/bin/env python3

import argparse
import os

def parse_tempercore(source_code):
    stdlib_import = False
    python_lines = []

    lines = source_code.splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("use stdlib"):
            stdlib_import = True
            continue

        tokens = {
            "function": "def",
            "let": "",
            "define": "",
            "call": "",
            "print": "print",
            "return": "return",
            "if": "if",
            "then": ":",
            "else": "else:",
            "while": "while",
            "loop": "for _ in range",
            "push": ".append",
            "into": "",
        }

        for key, val in tokens.items():
            if key in stripped:
                stripped = stripped.replace(key, val)

        if "append" in stripped and "to" in stripped:
            stripped = stripped.replace(" to ", ".append(") + ")"

        python_lines.append("    " + stripped)

    result = []
    if stdlib_import:
        result.append("from stdlib import TempercoreStdLib as T")
    result.append("def main():")
    result.extend(python_lines)
    result.append("\nif __name__ == '__main__':")
    result.append("    main()")
    return "\n".join(result)

def compile_tempercore_file(input_file, output_file):
    with open(input_file, 'r') as f:
        source_code = f.read()

    python_code = parse_tempercore(source_code)
    with open(output_file, 'w') as f:
        f.write("# Auto-generated from .tpc Tempercore\n")
        f.write(python_code + "\n")

    print(f"Compiled {input_file} -> {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Tempercore CLI Compiler with Stdlib')
    parser.add_argument('input', help='Input .tpc file')
    parser.add_argument('--output', help='Output .py file', default='out.py')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print("Input file not found.")
        return

    compile_tempercore_file(args.input, args.output)

if __name__ == "__main__":
    main()
