import re

def tokenize(code):
    token_specification = [
        ('NUMBER',   r'\d+(\.\d*)?'),
        ('ASSIGN',   r'='),
        ('END',      r':'),
        ('ID',       r'[A-Za-z_][A-Za-z0-9_]*'),
        ('STRING',   r'"[^"]*"'),
        ('OP',       r'[\+\-\*/%]'),
        ('KEYWORD',  r'\\b(let|define|append|if|then|while|do|stack|heap|var|getvar|delvar|vars|clearvars|compile|label|jmp|jz|jnz|call|ret|add|sub|mul|div|mod|neg|cmp|print|pause|break|continue|nop|error|mov)\\b'),
        ('NEWLINE',  r'\\n'),
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

def parse(tokens):
    ast = []
    idx = 0
    while idx < len(tokens):
        kind, val = tokens[idx]
        if val == 'stack':
            if tokens[idx+1][1] == 'push':
                ast.append(('stack_push', tokens[idx+2][1]))
                idx += 3
            elif tokens[idx+1][1] == 'pop':
                ast.append(('stack_pop',))
                idx += 2
        elif val == 'heap':
            action = tokens[idx+1][1]
            if action == 'allocate':
                ast.append(('heap_alloc', tokens[idx+2][1], tokens[idx+3][1]))
                idx += 4
            elif action == 'delete':
                ast.append(('heap_delete', tokens[idx+2][1]))
                idx += 3
        elif val == 'var':
            ast.append(('var_decl', tokens[idx+1][1], tokens[idx+2][1]))
            idx += 3
        elif val == 'mov':
            ast.append(('mov', tokens[idx+1][1], tokens[idx+2][1]))
            idx += 3
        elif val in {'add', 'sub', 'mul', 'div', 'mod', 'neg', 'cmp'}:
            ast.append(('op', val))
            idx += 1
        elif val in {'jmp', 'jz', 'jnz', 'call'}:
            ast.append(('jump', val, tokens[idx+1][1]))
            idx += 2
        elif val == 'ret':
            ast.append(('ret',))
            idx += 1
        elif val == 'label':
            ast.append(('label', tokens[idx+1][1]))
            idx += 2
        elif val in {'pause', 'continue', 'break', 'nop', 'print'}:
            ast.append(('meta', val))
            idx += 1
        elif val == 'error':
            ast.append(('error', tokens[idx+1][1]))
            idx += 2
        else:
            idx += 1
    return ast

def generate_divseq(ast):
    lines = []
    for node in ast:
        if node[0] == 'stack_push':
            lines.append(f"stack push {node[1]}")
        elif node[0] == 'stack_pop':
            lines.append("stack pop")
        elif node[0] == 'heap_alloc':
            lines.append(f"heap allocate {node[1]} {node[2]}")
        elif node[0] == 'heap_delete':
            lines.append(f"heap delete {node[1]}")
        elif node[0] == 'var_decl':
            lines.append(f"var {node[1]} {node[2]}")
        elif node[0] == 'mov':
            lines.append(f"mov {node[1]} {node[2]}")
        elif node[0] == 'op':
            lines.append(node[1])
        elif node[0] == 'jump':
            lines.append(f"{node[1]} {node[2]}")
        elif node[0] == 'ret':
            lines.append("ret")
        elif node[0] == 'label':
            lines.append(f"label {node[1]}")
        elif node[0] == 'meta':
            lines.append(node[1])
        elif node[0] == 'error':
            lines.append(f"error {node[1]}")
    return lines

def divseq_to_nasm(ir):
    asm = ["section .text", "global _start", "_start:"]
    for line in ir:
        tokens = line.split()
        cmd = tokens[0]
        if cmd == "stack" and tokens[1] == "push":
            asm.append(f"    mov rax, {tokens[2]}")
            asm.append("    push rax")
        elif cmd == "stack" and tokens[1] == "pop":
            asm.append("    pop rax")
        elif cmd == "add":
            asm += ["    pop rax", "    pop rbx", "    add rax, rbx", "    push rax"]
        elif cmd == "sub":
            asm += ["    pop rax", "    pop rbx", "    sub rbx, rax", "    push rbx"]
        elif cmd == "mul":
            asm += ["    pop rax", "    pop rbx", "    imul rax, rbx", "    push rax"]
        elif cmd == "div":
            asm += ["    pop rbx", "    pop rax", "    cqo", "    idiv rbx", "    push rax"]
        elif cmd == "mod":
            asm += ["    pop rbx", "    pop rax", "    cqo", "    idiv rbx", "    push rdx"]
        elif cmd == "neg":
            asm += ["    pop rax", "    neg rax", "    push rax"]
        elif cmd == "cmp":
            asm += ["    pop rax", "    pop rbx", "    cmp rbx, rax"]
        elif cmd == "jmp":
            asm.append(f"    jmp {tokens[1]}")
        elif cmd == "jz":
            asm += ["    pop rax", "    test rax, rax", f"    jz {tokens[1]}"]
        elif cmd == "jnz":
            asm += ["    pop rax", "    test rax, rax", f"    jnz {tokens[1]}"]
        elif cmd == "call":
            asm.append(f"    call {tokens[1]}")
        elif cmd == "ret":
            asm.append("    ret")
        elif cmd == "label":
            asm.append(f"{tokens[1]}:")
        elif cmd == "print":
            asm.append("    ; print (not implemented)")
        elif cmd == "pause":
            asm.append("    ; pause (no-op)")
        elif cmd == "continue":
            asm.append("    ; continue (no-op)")
        elif cmd == "break":
            asm.append("    ; break (no-op)")
        elif cmd == "nop":
            asm.append("    nop")
        elif cmd == "error":
            asm.append(f"    ; error {tokens[1]}")
        elif cmd == "var":
            asm.append(f"    ; var {tokens[1]} = {tokens[2]}")
        elif cmd == "mov":
            asm.append(f"    mov {tokens[1]}, {tokens[2]}")
    asm += ["    mov rax, 60", "    xor rdi, rdi", "    syscall"]
    return asm

from keystone import Ks, KS_ARCH_X86, KS_MODE_64
import mmap
import ctypes

def assemble_and_execute(asm_code):
    print("\n[🔧 AOT+JIT] Assembling and Executing...")

    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, count = ks.asm(asm_code)
        machine_code = bytes(encoding)
        print("[Keystone] Machine code (hex):", machine_code.hex())

        size = len(machine_code)
        mm = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        mm.write(machine_code)
        mm.seek(0)

        FUNC_TYPE = ctypes.CFUNCTYPE(None)
        address = ctypes.addressof(ctypes.c_char.from_buffer(mm))
        func = FUNC_TYPE(address)

        print("[JIT] Executing machine code now:")
        func()
        mm.close()
    except Exception as e:
        print("[Error] JIT Execution Failed:", str(e))

from temperc_lexer import tokenize
from temperc_parser import parse
from divseq_generator import generate_divseq
from asm_generator import divseq_to_nasm
from jit_exec import assemble_and_execute

with open("input.tpc", "r") as f:
    code = f.read()

tokens = tokenize(code)
ast = parse(tokens)
ir = generate_divseq(ast)

with open("output.divseq", "w") as f:
    f.write("\n".join(ir))

asm = divseq_to_nasm(ir)
asm_code = "\n".join(asm)

with open("output.asm", "w") as f:
    f.write(asm_code)

print("✅ Compilation complete. Attempting JIT Execution:")
assemble_and_execute(asm_code)





