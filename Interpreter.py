# temperc_lexer.py
import re

def tokenize(code):
    token_specification = [
        ('NUMBER',   r'\d+(\.\d*)?'),
        ('ASSIGN',   r'='),
        ('END',      r':'),
        ('ID',       r'[A-Za-z_][A-Za-z0-9_]*'),
        ('STRING',   r'"[^"]*"'),
        ('OP',       r'[\+\-\*/%]'),
        ('NEWLINE',  r'\n'),
        ('SKIP',     r'[ \t]+'),
        ('MISMATCH', r'.')
    ]
    tok_regex = '|'.join(f'(?P<{name}>{regex})' for name, regex in token_specification)
    tokens = []
    for mo in re.finditer(tok_regex, code):
        kind = mo.lastgroup
        value = mo.group()
        if kind == 'NUMBER':
            value = float(value) if '.' in value else int(value)
        elif kind == 'STRING':
            value = value.strip('"')
        elif kind in ('SKIP', 'NEWLINE'):
            continue
        elif kind == 'MISMATCH':
            raise SyntaxError(f'Unexpected character: {value}')
        tokens.append((kind, value))
    return tokens

# temperc_parser.py
def parse(tokens):
    ast = []
    idx = 0
    while idx < len(tokens):
        if tokens[idx][1] == 'let':
            var = tokens[idx+1][1]
            val = tokens[idx+3][1]
            ast.append(('assign', var, val))
            idx += 4
        elif tokens[idx][1] == 'define':
            if tokens[idx+1][1] == 'list':
                name = tokens[idx+2][1]
                ast.append(('list_decl', name))
                idx += 4
        elif tokens[idx][1] == 'append':
            val = tokens[idx+1][1]
            name = tokens[idx+3][1]
            ast.append(('append', name, val))
            idx += 4
        else:
            idx += 1
    return ast

# divseq_generator.py
def generate_divseq(ast):
    lines = []
    for node in ast:
        if node[0] == 'assign':
            lines.append(f"LOAD_CONST {node[1]}, {node[2]}")
        elif node[0] == 'list_decl':
            lines.append(f"ALLOC_ARRAY {node[1]}, STRING")
        elif node[0] == 'append':
            lines.append(f'APPEND {node[1]}, "{node[2]}"')
    return lines

# asm_generator.py
def divseq_to_nasm(ir):
    asm = ["section .data"]
    for line in ir:
        if line.startswith("LOAD_CONST"):
            _, var, val = line.split()
            asm.append(f"{var} dq {val}")
        elif line.startswith("ALLOC_ARRAY"):
            _, name, _ = line.split()
            asm.append(f"{name} times 10 dq 0")
    asm.append("\nsection .text")
    asm.append("global _start")
    asm.append("_start:")
    asm.append("    mov rax, 60")
    asm.append("    xor rdi, rdi")
    asm.append("    syscall")
    return asm

# main.py
from temperc_lexer import tokenize
from temperc_parser import parse
from divseq_generator import generate_divseq
from asm_generator import divseq_to_nasm

with open("input.tpc", "r") as f:
    code = f.read()

tokens = tokenize(code)
ast = parse(tokens)
ir = generate_divseq(ast)

with open("output.divseq", "w") as f:
    f.write("\n".join(ir))

asm = divseq_to_nasm(ir)
with open("output.asm", "w") as f:
    f.write("\n".join(asm))

print("✅ Compilation pipeline complete.")

