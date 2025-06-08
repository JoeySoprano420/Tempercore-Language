import threading
from stdlib import TempercoreStdLib as T

class Stack:
    def __init__(self):
        self.stack = []

    def push(self, val):
        self.stack.append(val)
        self.display()

    def pop(self):
        val = self.stack.pop() if self.stack else None
        self.display()
        return val

    def peek(self):
        return self.stack[-1] if self.stack else None

    def clear(self):
        self.stack.clear()
        self.display()

    def size(self):
        return len(self.stack)

    def display(self):
        print("\n[STACK]")
        for i, item in enumerate(reversed(self.stack)):
            print(f"{len(self.stack) - i}: {item}")
        print("-" * 20)

class Heap:
    def __init__(self):
        self.heap = {}
        self.lock = threading.Lock()

    def allocate(self, name, value):
        with self.lock:
            self.heap[name] = value
            self.display()

    def retrieve(self, name):
        with self.lock:
            return self.heap.get(name, None)

    def delete(self, name):
        with self.lock:
            if name in self.heap:
                del self.heap[name]
                self.display()

    def clear(self):
        with self.lock:
            self.heap.clear()
            self.display()

    def keys(self):
        with self.lock:
            return list(self.heap.keys())

    def dump(self):
        with self.lock:
            return dict(self.heap)

    def display(self):
        print("\n[HEAP]")
        for k, v in self.heap.items():
            print(f"{k} => {v}")
        print("-" * 20)

stack = Stack()
heap = Heap()

# --- Extension System ---
class Extension:
    def handle(self, tokens):
        raise NotImplementedError

    def help(self):
        return ""

# --- Existing Extensions (Web, GUI, ML, etc.) ---
class WebExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "web":
            if len(tokens) < 2:
                print("[Web] Missing subcommand.")
                return True
            if tokens[1] == "serve":
                print("[Web] Simulating web server at", tokens[2] if len(tokens) > 2 else "<missing address>")
            elif tokens[1] == "request":
                print("[Web] Simulating HTTP request to", tokens[2] if len(tokens) > 2 else "<missing url>")
            elif tokens[1] == "socket":
                print("[Web] Simulating websocket connection to", tokens[2] if len(tokens) > 2 else "<missing url>")
            else:
                print("[Web] Unknown web command")
            return True
        return False
    def help(self):
        return "web serve <address>, web request <url>, web socket <url>"

class GUIExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "gui":
            if len(tokens) < 2:
                print("[GUI] Missing subcommand.")
                return True
            if tokens[1] == "window":
                print("[GUI] Simulating window with title:", " ".join(tokens[2:]))
            elif tokens[1] == "button":
                print("[GUI] Simulating button:", " ".join(tokens[2:]))
            elif tokens[1] == "label":
                print("[GUI] Simulating label:", " ".join(tokens[2:]))
            else:
                print("[GUI] Unknown GUI command")
            return True
        return False
    def help(self):
        return "gui window <title>, gui button <label>, gui label <text>"

class MLExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "ml":
            if len(tokens) < 2:
                print("[ML] Missing subcommand.")
                return True
            if tokens[1] == "train":
                print("[ML] Simulating model training on data:", tokens[2] if len(tokens) > 2 else "<missing data>")
            elif tokens[1] == "predict":
                print("[ML] Simulating prediction for input:", tokens[2] if len(tokens) > 2 else "<missing input>")
            elif tokens[1] == "evaluate":
                print("[ML] Simulating model evaluation on:", tokens[2] if len(tokens) > 2 else "<missing data>")
            else:
                print("[ML] Unknown ML command")
            return True
        return False
    def help(self):
        return "ml train <data>, ml predict <input>, ml evaluate <data>"

class MobileExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "mobile":
            if len(tokens) < 2:
                print("[Mobile] Missing subcommand.")
                return True
            if tokens[1] == "build":
                print("[Mobile] Simulating mobile app build for platform:", tokens[2] if len(tokens) > 2 else "<missing platform>")
            elif tokens[1] == "deploy":
                print("[Mobile] Simulating mobile app deployment to:", tokens[2] if len(tokens) > 2 else "<missing device>")
            else:
                print("[Mobile] Unknown mobile command")
            return True
        return False
    def help(self):
        return "mobile build <platform>, mobile deploy <device>"

class GameExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "game":
            if len(tokens) < 2:
                print("[Game] Missing subcommand.")
                return True
            if tokens[1] == "start":
                print("[Game] Simulating game engine start")
            elif tokens[1] == "entity":
                print("[Game] Simulating entity creation:", " ".join(tokens[2:]))
            elif tokens[1] == "event":
                print("[Game] Simulating game event:", " ".join(tokens[2:]))
            else:
                print("[Game] Unknown game command")
            return True
        return False
    def help(self):
        return "game start, game entity <name>, game event <event>"

# --- Machine Code Generation ---
class CodeGenerator:
    def __init__(self):
        self.instructions = []

    def emit(self, instr):
        self.instructions.append(instr)

    def generate_stack_push(self, value):
        # Simulate pushing a value onto the stack (x86-64)
        self.emit(f"    ; push {value}")
        self.emit(f"    mov rax, {value}")
        self.emit(f"    push rax")

    def generate_stack_pop(self):
        self.emit("    ; pop")
        self.emit("    pop rax")

    def generate_print(self):
        self.emit("    ; print (simulated, would require syscall in real code)")

    def output(self):
        # Output as x86-64 assembly (for demonstration)
        return "\n".join([
            "section .text",
            "global _start",
            "_start:",
            *self.instructions,
            "    ; exit (simulated)",
            "    mov rax, 60",
            "    xor rdi, rdi",
            "    syscall"
        ])

class MachineCodeExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "compile":
            # Example: compile stack push 42 stack pop
            codegen = CodeGenerator()
            i = 1
            while i < len(tokens):
                if tokens[i] == "stack" and i+2 < len(tokens) and tokens[i+1] == "push":
                    codegen.generate_stack_push(tokens[i+2])
                    i += 3
                elif tokens[i] == "stack" and i+1 < len(tokens) and tokens[i+1] == "pop":
                    codegen.generate_stack_pop()
                    i += 2
                elif tokens[i] == "print":
                    codegen.generate_print()
                    i += 1
                else:
                    print(f"[MachineCode] Unknown or unsupported command: {' '.join(tokens[i:i+3])}")
                    i += 1
            print("\n[Generated x86-64 Assembly]:\n")
            print(codegen.output())
            return True
        return False
    def help(self):
        return "compile <commands...>   # Outputs x86-64 assembly for supported commands"

# Register extensions
extensions = [
    WebExtension(),
    GUIExtension(),
    MLExtension(),
    MobileExtension(),
    GameExtension(),
    MachineCodeExtension(),  # Add the machine code extension
]

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        return

    # Try extensions first
    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[{ext.__class__.__name__}] Error: {e}")
            return

    command = tokens[0]
    try:
        if command == "stack":
            if tokens[1] == "push":
                value = " ".join(tokens[2:])
                stack.push(value)
            elif tokens[1] == "pop":
                print("Popped:", stack.pop())
            elif tokens[1] == "peek":
                print("Top of stack:", stack.peek())
            elif tokens[1] == "clear":
                stack.clear()
            elif tokens[1] == "size":
                print("Stack size:", stack.size())
            else:
                print("[Stack] Unknown stack command")
        elif command == "heap":
            action = tokens[1]
            if action == "allocate":
                name = tokens[2]
                value = " ".join(tokens[3:])
                heap.allocate(name, value)
            elif action == "get":
                name = tokens[2]
                print(f"{name} =", heap.retrieve(name))
            elif action == "delete":
                heap.delete(tokens[2])
            elif action == "dump":
                print(heap.dump())
            elif action == "clear":
                heap.clear()
            elif action == "keys":
                print("Heap keys:", heap.keys())
            else:
                print("[Heap] Unknown heap command")
        elif command == "stdlib":
            fn = tokens[1]
            args = [eval(arg) for arg in tokens[2:]]
            if hasattr(T, fn):
                result = getattr(T, fn)(*args)
                print(f"Result of {fn}:", result)
            else:
                print(f"Function {fn} not found in stdlib")
        else:
            print(f"Unknown command: {cmd}")
    except Exception as e:
        print(f"[Interpreter] Error: {e}")

        import threading
import ctypes
import mmap
from stdlib import TempercoreStdLib as T

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

class Stack:
    def __init__(self):
        self.stack = []

    def push(self, val):
        self.stack.append(val)
        self.display()

    def pop(self):
        val = self.stack.pop() if self.stack else None
        self.display()
        return val

    def peek(self):
        return self.stack[-1] if self.stack else None

    def clear(self):
        self.stack.clear()
        self.display()

    def size(self):
        return len(self.stack)

    def display(self):
        print("\n[STACK]")
        for i, item in enumerate(reversed(self.stack)):
            print(f"{len(self.stack) - i}: {item}")
        print("-" * 20)

class Heap:
    def __init__(self):
        self.heap = {}
        self.lock = threading.Lock()

    def allocate(self, name, value):
        with self.lock:
            self.heap[name] = value
            self.display()

    def retrieve(self, name):
        with self.lock:
            return self.heap.get(name, None)

    def delete(self, name):
        with self.lock:
            if name in self.heap:
                del self.heap[name]
                self.display()

    def clear(self):
        with self.lock:
            self.heap.clear()
            self.display()

    def keys(self):
        with self.lock:
            return list(self.heap.keys())

    def dump(self):
        with self.lock:
            return dict(self.heap)

    def display(self):
        print("\n[HEAP]")
        for k, v in self.heap.items():
            print(f"{k} => {v}")
        print("-" * 20)

stack = Stack()
heap = Heap()

# --- Extension System ---
class Extension:
    def handle(self, tokens):
        raise NotImplementedError

    def help(self):
        return ""

# --- Existing Extensions (Web, GUI, ML, etc.) ---
class WebExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "web":
            if len(tokens) < 2:
                print("[Web] Missing subcommand.")
                return True
            if tokens[1] == "serve":
                print("[Web] Simulating web server at", tokens[2] if len(tokens) > 2 else "<missing address>")
            elif tokens[1] == "request":
                print("[Web] Simulating HTTP request to", tokens[2] if len(tokens) > 2 else "<missing url>")
            elif tokens[1] == "socket":
                print("[Web] Simulating websocket connection to", tokens[2] if len(tokens) > 2 else "<missing url>")
            else:
                print("[Web] Unknown web command")
            return True
        return False
    def help(self):
        return "web serve <address>, web request <url>, web socket <url>"

class GUIExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "gui":
            if len(tokens) < 2:
                print("[GUI] Missing subcommand.")
                return True
            if tokens[1] == "window":
                print("[GUI] Simulating window with title:", " ".join(tokens[2:]))
            elif tokens[1] == "button":
                print("[GUI] Simulating button:", " ".join(tokens[2:]))
            elif tokens[1] == "label":
                print("[GUI] Simulating label:", " ".join(tokens[2:]))
            else:
                print("[GUI] Unknown GUI command")
            return True
        return False
    def help(self):
        return "gui window <title>, gui button <label>, gui label <text>"

class MLExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "ml":
            if len(tokens) < 2:
                print("[ML] Missing subcommand.")
                return True
            if tokens[1] == "train":
                print("[ML] Simulating model training on data:", tokens[2] if len(tokens) > 2 else "<missing data>")
            elif tokens[1] == "predict":
                print("[ML] Simulating prediction for input:", tokens[2] if len(tokens) > 2 else "<missing input>")
            elif tokens[1] == "evaluate":
                print("[ML] Simulating model evaluation on:", tokens[2] if len(tokens) > 2 else "<missing data>")
            else:
                print("[ML] Unknown ML command")
            return True
        return False
    def help(self):
        return "ml train <data>, ml predict <input>, ml evaluate <data>"

class MobileExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "mobile":
            if len(tokens) < 2:
                print("[Mobile] Missing subcommand.")
                return True
            if tokens[1] == "build":
                print("[Mobile] Simulating mobile app build for platform:", tokens[2] if len(tokens) > 2 else "<missing platform>")
            elif tokens[1] == "deploy":
                print("[Mobile] Simulating mobile app deployment to:", tokens[2] if len(tokens) > 2 else "<missing device>")
            else:
                print("[Mobile] Unknown mobile command")
            return True
        return False
    def help(self):
        return "mobile build <platform>, mobile deploy <device>"

class GameExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "game":
            if len(tokens) < 2:
                print("[Game] Missing subcommand.")
                return True
            if tokens[1] == "start":
                print("[Game] Simulating game engine start")
            elif tokens[1] == "entity":
                print("[Game] Simulating entity creation:", " ".join(tokens[2:]))
            elif tokens[1] == "event":
                print("[Game] Simulating game event:", " ".join(tokens[2:]))
            else:
                print("[Game] Unknown game command")
            return True
        return False
    def help(self):
        return "game start, game entity <name>, game event <event>"

# --- Machine Code Generation ---
class CodeGenerator:
    def __init__(self):
        self.instructions = []

    def emit(self, instr):
        self.instructions.append(instr)

    def generate_stack_push(self, value):
        self.emit(f"    mov rax, {value}")
        self.emit(f"    push rax")

    def generate_stack_pop(self):
        self.emit("    pop rax")

    def generate_print(self):
        # This is a placeholder; real print would require syscall and buffer setup
        self.emit("    ; print (not implemented)")

    def output(self):
        return "\n".join([
            "section .text",
            "global _start",
            "_start:",
            *self.instructions,
            "    mov rax, 60",
            "    xor rdi, rdi",
            "    syscall"
        ])

    def output_bytes(self):
        # Returns the instructions as a single string for Keystone
        return "\n".join(self.instructions)

class MachineCodeExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "compile":
            codegen = CodeGenerator()
            i = 1
            while i < len(tokens):
                if tokens[i] == "stack" and i+2 < len(tokens) and tokens[i+1] == "push":
                    codegen.generate_stack_push(tokens[i+2])
                    i += 3
                elif tokens[i] == "stack" and i+1 < len(tokens) and tokens[i+1] == "pop":
                    codegen.generate_stack_pop()
                    i += 2
                elif tokens[i] == "print":
                    codegen.generate_print()
                    i += 1
                else:
                    print(f"[MachineCode] Unknown or unsupported command: {' '.join(tokens[i:i+3])}")
                    i += 1

            print("\n[Generated x86-64 Assembly]:\n")
            asm = codegen.output()
            print(asm)

            if not KEYSTONE_AVAILABLE:
                print("\n[Keystone] Keystone assembler not available. Install with 'pip install keystone-engine'.")
                return True

            # --- Keystone AOT Compilation ---
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_64)
                encoding, count = ks.asm(asm)
                machine_code = bytes(encoding)
                print("\n[Keystone] Machine code (hex):")
                print(machine_code.hex())
            except Exception as e:
                print(f"[Keystone] Assembly error: {e}")
                return True

            # --- JIT Execution using mmap and ctypes ---
            try:
                # Allocate RWX memory
                size = len(machine_code)
                mm = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
                mm.write(machine_code)
                # Move pointer to start
                mm.seek(0)
                # Get function pointer
                FUNC_TYPE = ctypes.CFUNCTYPE(None)
                address = ctypes.addressof(ctypes.c_char.from_buffer(mm))
                func = FUNC_TYPE(address)
                print("\n[JIT] Executing machine code (may not print output, but will exit):")
                func()
                mm.close()
            except Exception as e:
                print(f"[JIT] Execution error: {e}")
            return True
        return False

    def help(self):
        return "compile <commands...>   # Outputs x86-64 assembly, machine code, and JIT executes (if possible)"

# Register extensions
extensions = [
    WebExtension(),
    GUIExtension(),
    MLExtension(),
    MobileExtension(),
    GameExtension(),
    MachineCodeExtension(),
]

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        return

    # Try extensions first
    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[{ext.__class__.__name__}] Error: {e}")
            return

    command = tokens[0]
    try:
        if command == "stack":
            if tokens[1] == "push":
                value = " ".join(tokens[2:])
                stack.push(value)
            elif tokens[1] == "pop":
                print("Popped:", stack.pop())
            elif tokens[1] == "peek":
                print("Top of stack:", stack.peek())
            elif tokens[1] == "clear":
                stack.clear()
            elif tokens[1] == "size":
                print("Stack size:", stack.size())
            else:
                print("[Stack] Unknown stack command")
        elif command == "heap":
            action = tokens[1]
            if action == "allocate":
                name = tokens[2]
                value = " ".join(tokens[3:])
                heap.allocate(name, value)
            elif action == "get":
                name = tokens[2]
                print(f"{name} =", heap.retrieve(name))
            elif action == "delete":
                heap.delete(tokens[2])
            elif action == "dump":
                print(heap.dump())
            elif action == "clear":
                heap.clear()
            elif action == "keys":
                print("Heap keys:", heap.keys())
            else:
                print("[Heap] Unknown heap command")
        elif command == "stdlib":
            fn = tokens[1]
            args = [eval(arg) for arg in tokens[2:]]
            if hasattr(T, fn):
                result = getattr(T, fn)(*args)
                print(f"Result of {fn}:", result)
            else:
                print(f"Function {fn} not found in stdlib")
        else:
            print(f"Unknown command: {cmd}")
    except Exception as e:
        print(f"[Interpreter] Error: {e}")

import threading
import ctypes
import mmap
from stdlib import TempercoreStdLib as T

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

class Stack:
    def __init__(self):
        self.stack = []

    def push(self, val):
        self.stack.append(val)
        self.display()

    def pop(self):
        val = self.stack.pop() if self.stack else None
        self.display()
        return val

    def peek(self):
        return self.stack[-1] if self.stack else None

    def clear(self):
        self.stack.clear()
        self.display()

    def size(self):
        return len(self.stack)

    def display(self):
        print("\n[STACK]")
        for i, item in enumerate(reversed(self.stack)):
            print(f"{len(self.stack) - i}: {item}")
        print("-" * 20)

class Heap:
    def __init__(self):
        self.heap = {}
        self.lock = threading.Lock()

    def allocate(self, name, value):
        with self.lock:
            self.heap[name] = value
            self.display()

    def retrieve(self, name):
        with self.lock:
            return self.heap.get(name, None)

    def delete(self, name):
        with self.lock:
            if name in self.heap:
                del self.heap[name]
                self.display()

    def clear(self):
        with self.lock:
            self.heap.clear()
            self.display()

    def keys(self):
        with self.lock:
            return list(self.heap.keys())

    def dump(self):
        with self.lock:
            return dict(self.heap)

    def display(self):
        print("\n[HEAP]")
        for k, v in self.heap.items():
            print(f"{k} => {v}")
        print("-" * 20)

stack = Stack()
heap = Heap()

# --- Extension System ---
class Extension:
    def handle(self, tokens):
        raise NotImplementedError

    def help(self):
        return ""

# --- Existing Extensions (Web, GUI, ML, etc.) ---
class WebExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "web":
            if len(tokens) < 2:
                print("[Web] Missing subcommand.")
                return True
            if tokens[1] == "serve":
                print("[Web] Simulating web server at", tokens[2] if len(tokens) > 2 else "<missing address>")
            elif tokens[1] == "request":
                print("[Web] Simulating HTTP request to", tokens[2] if len(tokens) > 2 else "<missing url>")
            elif tokens[1] == "socket":
                print("[Web] Simulating websocket connection to", tokens[2] if len(tokens) > 2 else "<missing url>")
            else:
                print("[Web] Unknown web command")
            return True
        return False
    def help(self):
        return "web serve <address>, web request <url>, web socket <url>"

class GUIExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "gui":
            if len(tokens) < 2:
                print("[GUI] Missing subcommand.")
                return True
            if tokens[1] == "window":
                print("[GUI] Simulating window with title:", " ".join(tokens[2:]))
            elif tokens[1] == "button":
                print("[GUI] Simulating button:", " ".join(tokens[2:]))
            elif tokens[1] == "label":
                print("[GUI] Simulating label:", " ".join(tokens[2:]))
            else:
                print("[GUI] Unknown GUI command")
            return True
        return False
    def help(self):
        return "gui window <title>, gui button <label>, gui label <text>"

class MLExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "ml":
            if len(tokens) < 2:
                print("[ML] Missing subcommand.")
                return True
            if tokens[1] == "train":
                print("[ML] Simulating model training on data:", tokens[2] if len(tokens) > 2 else "<missing data>")
            elif tokens[1] == "predict":
                print("[ML] Simulating prediction for input:", tokens[2] if len(tokens) > 2 else "<missing input>")
            elif tokens[1] == "evaluate":
                print("[ML] Simulating model evaluation on:", tokens[2] if len(tokens) > 2 else "<missing data>")
            else:
                print("[ML] Unknown ML command")
            return True
        return False
    def help(self):
        return "ml train <data>, ml predict <input>, ml evaluate <data>"

class MobileExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "mobile":
            if len(tokens) < 2:
                print("[Mobile] Missing subcommand.")
                return True
            if tokens[1] == "build":
                print("[Mobile] Simulating mobile app build for platform:", tokens[2] if len(tokens) > 2 else "<missing platform>")
            elif tokens[1] == "deploy":
                print("[Mobile] Simulating mobile app deployment to:", tokens[2] if len(tokens) > 2 else "<missing device>")
            else:
                print("[Mobile] Unknown mobile command")
            return True
        return False
    def help(self):
        return "mobile build <platform>, mobile deploy <device>"

class GameExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "game":
            if len(tokens) < 2:
                print("[Game] Missing subcommand.")
                return True
            if tokens[1] == "start":
                print("[Game] Simulating game engine start")
            elif tokens[1] == "entity":
                print("[Game] Simulating entity creation:", " ".join(tokens[2:]))
            elif tokens[1] == "event":
                print("[Game] Simulating game event:", " ".join(tokens[2:]))
            else:
                print("[Game] Unknown game command")
            return True
        return False
    def help(self):
        return "game start, game entity <name>, game event <event>"

# --- Machine Code Generation ---
class CodeGenerator:
    def __init__(self):
        self.instructions = []

    def emit(self, instr):
        self.instructions.append(instr)

    def generate_stack_push(self, value):
        self.emit(f"    ; push {value}")
        self.emit(f"    mov rax, {value}")
        self.emit(f"    push rax")

    def generate_stack_pop(self):
        self.emit("    ; pop")
        self.emit("    pop rax")

    def generate_add(self):
        self.emit("    ; add (pop rax, pop rbx, add rax, rbx, push rax)")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    add rax, rbx")
        self.emit("    push rax")

    def generate_sub(self):
        self.emit("    ; sub (pop rax, pop rbx, sub rbx, rax, push rbx)")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    sub rbx, rax")
        self.emit("    push rbx")

    def generate_mul(self):
        self.emit("    ; mul (pop rax, pop rbx, imul rax, rbx, push rax)")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    imul rax, rbx")
        self.emit("    push rax")

    def generate_div(self):
        self.emit("    ; div (pop rbx, pop rax, cqo, idiv rbx, push rax)")
        self.emit("    pop rbx")  # divisor
        self.emit("    pop rax")  # dividend
        self.emit("    cqo")
        self.emit("    idiv rbx")
        self.emit("    push rax")

    def generate_print(self):
        # This is a placeholder; real print would require syscall and buffer setup
        self.emit("    ; print (not implemented)")

    def generate_label(self, label):
        self.emit(f"{label}:")

    def generate_jmp(self, label):
        self.emit(f"    jmp {label}")

    def generate_jz(self, label):
        self.emit("    pop rax")
        self.emit(f"    test rax, rax")
        self.emit(f"    jz {label}")

    def generate_jnz(self, label):
        self.emit("    pop rax")
        self.emit(f"    test rax, rax")
        self.emit(f"    jnz {label}")

    def output(self):
        return "\n".join([
            "section .text",
            "global _start",
            "_start:",
            *self.instructions,
            "    mov rax, 60",
            "    xor rdi, rdi",
            "    syscall"
        ])

    def output_bytes(self):
        return "\n".join(self.instructions)

class MachineCodeExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "compile":
            codegen = CodeGenerator()
            i = 1
            while i < len(tokens):
                if tokens[i] == "stack" and i+2 < len(tokens) and tokens[i+1] == "push":
                    codegen.generate_stack_push(tokens[i+2])
                    i += 3
                elif tokens[i] == "stack" and i+1 < len(tokens) and tokens[i+1] == "pop":
                    codegen.generate_stack_pop()
                    i += 2
                elif tokens[i] == "add":
                    codegen.generate_add()
                    i += 1
                elif tokens[i] == "sub":
                    codegen.generate_sub()
                    i += 1
                elif tokens[i] == "mul":
                    codegen.generate_mul()
                    i += 1
                elif tokens[i] == "div":
                    codegen.generate_div()
                    i += 1
                elif tokens[i] == "print":
                    codegen.generate_print()
                    i += 1
                elif tokens[i] == "label" and i+1 < len(tokens):
                    codegen.generate_label(tokens[i+1])
                    i += 2
                elif tokens[i] == "jmp" and i+1 < len(tokens):
                    codegen.generate_jmp(tokens[i+1])
                    i += 2
                elif tokens[i] == "jz" and i+1 < len(tokens):
                    codegen.generate_jz(tokens[i+1])
                    i += 2
                elif tokens[i] == "jnz" and i+1 < len(tokens):
                    codegen.generate_jnz(tokens[i+1])
                    i += 2
                else:
                    print(f"[MachineCode] Unknown or unsupported command: {' '.join(tokens[i:i+3])}")
                    i += 1

            print("\n[Generated x86-64 Assembly]:\n")
            asm = codegen.output()
            print(asm)

            if not KEYSTONE_AVAILABLE:
                print("\n[Keystone] Keystone assembler not available. Install with 'pip install keystone-engine'.")
                return True

            # --- Keystone AOT Compilation ---
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_64)
                encoding, count = ks.asm(asm)
                machine_code = bytes(encoding)
                print("\n[Keystone] Machine code (hex):")
                print(machine_code.hex())
            except Exception as e:
                print(f"[Keystone] Assembly error: {e}")
                return True

            # --- JIT Execution using mmap and ctypes ---
            try:
                size = len(machine_code)
                mm = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
                mm.write(machine_code)
                mm.seek(0)
                FUNC_TYPE = ctypes.CFUNCTYPE(None)
                address = ctypes.addressof(ctypes.c_char.from_buffer(mm))
                func = FUNC_TYPE(address)
                print("\n[JIT] Executing machine code (may not print output, but will exit):")
                func()
                mm.close()
            except Exception as e:
                print(f"[JIT] Execution error: {e}")
            return True
        return False

    def help(self):
        return (
            "compile <commands...>   # Outputs x86-64 assembly, machine code, and JIT executes (if possible)\n"
            "Supported: stack push <val>, stack pop, add, sub, mul, div, print, label <lbl>, jmp <lbl>, jz <lbl>, jnz <lbl>"
        )

# Register extensions
extensions = [
    WebExtension(),
    GUIExtension(),
    MLExtension(),
    MobileExtension(),
    GameExtension(),
    MachineCodeExtension(),
]

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        return

    # Try extensions first
    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[{ext.__class__.__name__}] Error: {e}")
            return

    command = tokens[0]
    try:
        if command == "stack":
            if tokens[1] == "push":
                value = " ".join(tokens[2:])
                stack.push(value)
            elif tokens[1] == "pop":
                print("Popped:", stack.pop())
            elif tokens[1] == "peek":
                print("Top of stack:", stack.peek())
            elif tokens[1] == "clear":
                stack.clear()
            elif tokens[1] == "size":
                print("Stack size:", stack.size())
            else:
                print("[Stack] Unknown stack command")
        elif command == "heap":
            action = tokens[1]
            if action == "allocate":
                name = tokens[2]
                value = " ".join(tokens[3:])
                heap.allocate(name, value)
            elif action == "get":
                name = tokens[2]
                print(f"{name} =", heap.retrieve(name))
            elif action == "delete":
                heap.delete(tokens[2])
            elif action == "dump":
                print(heap.dump())
            elif action == "clear":
                heap.clear()
            elif action == "keys":
                print("Heap keys:", heap.keys())
            else:
                print("[Heap] Unknown heap command")
        elif command == "stdlib":
            fn = tokens[1]
            args = [eval(arg) for arg in tokens[2:]]
            if hasattr(T, fn):
                result = getattr(T, fn)(*args)
                print(f"Result of {fn}:", result)
            else:
                print(f"Function {fn} not found in stdlib")
        else:
            print(f"Unknown command: {cmd}")
    except Exception as e:
        print(f"[Interpreter] Error: {e}")

        # ... [existing imports and classes above remain unchanged] ...

class CodeGenerator:
    def __init__(self):
        self.instructions = []
        self.labels = set()
        self.variables = {}
        self.var_offset = 0

    def emit(self, instr):
        self.instructions.append(instr)

    # --- Stack/Heap/Memory ---
    def generate_stack_push(self, value):
        self.emit(f"    ; stack push {value}")
        self.emit(f"    mov rax, {value}")
        self.emit(f"    push rax")

    def generate_stack_pop(self):
        self.emit("    ; stack pop")
        self.emit("    pop rax")

    def generate_heap_allocate(self, name, value):
        # Simulate heap allocation (not real heap, just a comment)
        self.emit(f"    ; heap allocate {name} = {value}")

    def generate_heap_delete(self, name):
        self.emit(f"    ; heap delete {name}")

    def generate_heap_dump(self):
        self.emit("    ; heap dump (not implemented)")

    # --- Arithmetic/Logic ---
    def generate_add(self):
        self.emit("    ; add")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    add rax, rbx")
        self.emit("    push rax")

    def generate_sub(self):
        self.emit("    ; sub")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    sub rbx, rax")
        self.emit("    push rbx")

    def generate_mul(self):
        self.emit("    ; mul")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    imul rax, rbx")
        self.emit("    push rax")

    def generate_div(self):
        self.emit("    ; div")
        self.emit("    pop rbx")
        self.emit("    pop rax")
        self.emit("    cqo")
        self.emit("    idiv rbx")
        self.emit("    push rax")

    def generate_neg(self):
        self.emit("    ; negate")
        self.emit("    pop rax")
        self.emit("    neg rax")
        self.emit("    push rax")

    def generate_mod(self):
        self.emit("    ; mod")
        self.emit("    pop rbx")
        self.emit("    pop rax")
        self.emit("    cqo")
        self.emit("    idiv rbx")
        self.emit("    push rdx")

    # --- Comparison/Conditionals ---
    def generate_cmp(self):
        self.emit("    ; compare")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    cmp rbx, rax")

    def generate_jmp(self, label):
        self.emit(f"    jmp {label}")

    def generate_jz(self, label):
        self.emit("    pop rax")
        self.emit("    test rax, rax")
        self.emit(f"    jz {label}")

    def generate_jnz(self, label):
        self.emit("    pop rax")
        self.emit("    test rax, rax")
        self.emit(f"    jnz {label}")

    def generate_label(self, label):
        self.labels.add(label)
        self.emit(f"{label}:")

    def generate_call(self, label):
        self.emit(f"    call {label}")

    def generate_ret(self):
        self.emit("    ret")

    # --- Buffer/IO/Flow ---
    def generate_print(self):
        self.emit("    ; print (not implemented)")

    def generate_pause(self):
        self.emit("    ; pause (not implemented)")

    def generate_continue(self):
        self.emit("    ; continue (not implemented)")

    def generate_break(self):
        self.emit("    ; break (not implemented)")

    # --- Variable/Assignment ---
    def generate_var(self, name, value):
        # Simulate variable assignment (not real memory)
        self.variables[name] = value
        self.emit(f"    ; var {name} = {value}")

    def generate_mov(self, dest, src):
        self.emit(f"    mov {dest}, {src}")

    # --- Error/Control ---
    def generate_error(self, msg):
        self.emit(f"    ; error: {msg}")

    def generate_nop(self):
        self.emit("    nop")

    # --- Output ---
    def output(self):
        return "\n".join([
            "section .text",
            "global _start",
            "_start:",
            *self.instructions,
            "    mov rax, 60",
            "    xor rdi, rdi",
            "    syscall"
        ])

    def output_bytes(self):
        return "\n".join(self.instructions)

class MachineCodeExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "compile":
            codegen = CodeGenerator()
            i = 1
            while i < len(tokens):
                t = tokens[i]
                if t == "stack" and i+2 < len(tokens) and tokens[i+1] == "push":
                    codegen.generate_stack_push(tokens[i+2])
                    i += 3
                elif t == "stack" and i+1 < len(tokens) and tokens[i+1] == "pop":
                    codegen.generate_stack_pop()
                    i += 2
                elif t == "heap" and i+2 < len(tokens) and tokens[i+1] == "allocate":
                    codegen.generate_heap_allocate(tokens[i+2], tokens[i+3] if i+3 < len(tokens) else "0")
                    i += 4
                elif t == "heap" and i+1 < len(tokens) and tokens[i+1] == "delete":
                    codegen.generate_heap_delete(tokens[i+2] if i+2 < len(tokens) else "")
                    i += 3
                elif t == "heap" and i+1 < len(tokens) and tokens[i+1] == "dump":
                    codegen.generate_heap_dump()
                    i += 2
                elif t == "add":
                    codegen.generate_add()
                    i += 1
                elif t == "sub":
                    codegen.generate_sub()
                    i += 1
                elif t == "mul":
                    codegen.generate_mul()
                    i += 1
                elif t == "div":
                    codegen.generate_div()
                    i += 1
                elif t == "neg":
                    codegen.generate_neg()
                    i += 1
                elif t == "mod":
                    codegen.generate_mod()
                    i += 1
                elif t == "cmp":
                    codegen.generate_cmp()
                    i += 1
                elif t == "jmp" and i+1 < len(tokens):
                    codegen.generate_jmp(tokens[i+1])
                    i += 2
                elif t == "jz" and i+1 < len(tokens):
                    codegen.generate_jz(tokens[i+1])
                    i += 2
                elif t == "jnz" and i+1 < len(tokens):
                    codegen.generate_jnz(tokens[i+1])
                    i += 2
                elif t == "label" and i+1 < len(tokens):
                    codegen.generate_label(tokens[i+1])
                    i += 2
                elif t == "call" and i+1 < len(tokens):
                    codegen.generate_call(tokens[i+1])
                    i += 2
                elif t == "ret":
                    codegen.generate_ret()
                    i += 1
                elif t == "var" and i+2 < len(tokens):
                    codegen.generate_var(tokens[i+1], tokens[i+2])
                    i += 3
                elif t == "mov" and i+2 < len(tokens):
                    codegen.generate_mov(tokens[i+1], tokens[i+2])
                    i += 3
                elif t == "print":
                    codegen.generate_print()
                    i += 1
                elif t == "pause":
                    codegen.generate_pause()
                    i += 1
                elif t == "continue":
                    codegen.generate_continue()
                    i += 1
                elif t == "break":
                    codegen.generate_break()
                    i += 1
                elif t == "nop":
                    codegen.generate_nop()
                    i += 1
                elif t == "error" and i+1 < len(tokens):
                    codegen.generate_error(tokens[i+1])
                    i += 2
                else:
                    # Passive correct or skip error handling
                    i += 1

            print("\n[Generated x86-64 Assembly]:\n")
            asm = codegen.output()
            print(asm)
            # AOT/JIT omitted for brevity, see previous code for integration
            return True
        return False

    def help(self):
        return (
            "compile <commands...>   # Outputs x86-64 assembly for supported commands\n"
            "Supported: stack push/pop, heap allocate/delete/dump, add, sub, mul, div, neg, mod, cmp, jmp, jz, jnz, label, call, ret, var, mov, print, pause, continue, break, nop, error"
        )

# Register extensions
extensions = [
    WebExtension(),
    GUIExtension(),
    MLExtension(),
    MobileExtension(),
    GameExtension(),
    MachineCodeExtension(),
]

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        return

    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[{ext.__class__.__name__}] Error: {e}")
            return

    command = tokens[0]
    try:
        if command == "stack":
            if tokens[1] == "push":
                value = " ".join(tokens[2:])
                stack.push(value)
            elif tokens[1] == "pop":
                print("Popped:", stack.pop())
            elif tokens[1] == "peek":
                print("Top of stack:", stack.peek())
            elif tokens[1] == "clear":
                stack.clear()
            elif tokens[1] == "size":
                print("Stack size:", stack.size())
            else:
                print("[Stack] Unknown stack command")
        elif command == "heap":
            action = tokens[1]
            if action == "allocate":
                name = tokens[2]
                value = " ".join(tokens[3:])
                heap.allocate(name, value)
            elif action == "get":
                name = tokens[2]
                print(f"{name} =", heap.retrieve(name))
            elif action == "delete":
                heap.delete(tokens[2])
            elif action == "dump":
                print(heap.dump())
            elif action == "clear":
                heap.clear()
            elif action == "keys":
                print("Heap keys:", heap.keys())
            else:
                print("[Heap] Unknown heap command")
        elif command == "stdlib":
            fn = tokens[1]
            args = [eval(arg) for arg in tokens[2:]]
            if hasattr(T, fn):
                result = getattr(T, fn)(*args)
                print(f"Result of {fn}:", result)
            else:
                print(f"Function {fn} not found in stdlib")
        else:
            print(f"Unknown command: {cmd}")
    except Exception as e:
        print(f"[Interpreter] Error: {e}")

        return True
        return False

    import threading
import ctypes
import sys
from stdlib import TempercoreStdLib as T

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

if sys.platform == "win32":
    import mmap
    import ctypes.wintypes

class Stack:
    def __init__(self):
        self.stack = []

    def push(self, val):
        self.stack.append(val)
        self.display()

    def pop(self):
        val = self.stack.pop() if self.stack else None
        self.display()
        return val

    def peek(self):
        return self.stack[-1] if self.stack else None

    def clear(self):
        self.stack.clear()
        self.display()

    def size(self):
        return len(self.stack)

    def display(self):
        print("\n[STACK]")
        for i, item in enumerate(reversed(self.stack)):
            print(f"{len(self.stack) - i}: {item}")
        print("-" * 20)

class Heap:
    def __init__(self):
        self.heap = {}
        self.lock = threading.Lock()

    def allocate(self, name, value):
        with self.lock:
            # Store the value as a bytes buffer for authenticity
            if isinstance(value, str):
                value_bytes = value.encode('utf-8')
            elif isinstance(value, (int, float)):
                value_bytes = str(value).encode('utf-8')
            elif isinstance(value, bytes):
                value_bytes = value
            else:
                value_bytes = str(value).encode('utf-8')
            buf = ctypes.create_string_buffer(value_bytes)
            self.heap[name] = buf
            self.display()

    def retrieve(self, name):
        with self.lock:
            buf = self.heap.get(name, None)
            if buf is not None:
                # Return as string for display, but keep as buffer internally
                return buf.value.decode('utf-8', errors='replace')
            return None

    def delete(self, name):
        with self.lock:
            if name in self.heap:
                del self.heap[name]
                self.display()

    def clear(self):
        with self.lock:
            self.heap.clear()
            self.display()

    def keys(self):
        with self.lock:
            return list(self.heap.keys())

    def dump(self):
        with self.lock:
            # Return a dict of name: value (decoded)
            return {k: v.value.decode('utf-8', errors='replace') for k, v in self.heap.items()}

    def display(self):
        print("\n[HEAP]")
        for k, v in self.heap.items():
            print(f"{k} => {v.value.decode('utf-8', errors='replace')}")
        print("-" * 20)

stack = Stack()
heap = Heap()

# --- Variable Table for Assignments ---
class VariableTable:
    def __init__(self):
        self.vars = {}
        self.lock = threading.Lock()

    def set(self, name, value):
        with self.lock:
            self.vars[name] = value

    def get(self, name):
        with self.lock:
            return self.vars.get(name, None)

    def delete(self, name):
        with self.lock:
            if name in self.vars:
                del self.vars[name]

    def clear(self):
        with self.lock:
            self.vars.clear()

    def dump(self):
        with self.lock:
            return dict(self.vars)

    def display(self):
        print("\n[VARIABLES]")
        for k, v in self.vars.items():
            print(f"{k} = {v}")
        print("-" * 20)

variables = VariableTable()

# --- Extension System ---
class Extension:
    def handle(self, tokens):
        raise NotImplementedError

    def help(self):
        return ""

# --- Existing Extensions (Web, GUI, ML, etc.) ---
class WebExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "web":
            if len(tokens) < 2:
                print("[Web] Missing subcommand.")
                return True
            if tokens[1] == "serve":
                print("[Web] Simulating web server at", tokens[2] if len(tokens) > 2 else "<missing address>")
            elif tokens[1] == "request":
                print("[Web] Simulating HTTP request to", tokens[2] if len(tokens) > 2 else "<missing url>")
            elif tokens[1] == "socket":
                print("[Web] Simulating websocket connection to", tokens[2] if len(tokens) > 2 else "<missing url>")
            else:
                print("[Web] Unknown web command")
            return True
        return False
    def help(self):
        return "web serve <address>, web request <url>, web socket <url>"

class GUIExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "gui":
            if len(tokens) < 2:
                print("[GUI] Missing subcommand.")
                return True
            if tokens[1] == "window":
                print("[GUI] Simulating window with title:", " ".join(tokens[2:]))
            elif tokens[1] == "button":
                print("[GUI] Simulating button:", " ".join(tokens[2:]))
            elif tokens[1] == "label":
                print("[GUI] Simulating label:", " ".join(tokens[2:]))
            else:
                print("[GUI] Unknown GUI command")
            return True
        return False
    def help(self):
        return "gui window <title>, gui button <label>, gui label <text>"

class MLExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "ml":
            if len(tokens) < 2:
                print("[ML] Missing subcommand.")
                return True
            if tokens[1] == "train":
                print("[ML] Simulating model training on data:", tokens[2] if len(tokens) > 2 else "<missing data>")
            elif tokens[1] == "predict":
                print("[ML] Simulating prediction for input:", tokens[2] if len(tokens) > 2 else "<missing input>")
            elif tokens[1] == "evaluate":
                print("[ML] Simulating model evaluation on:", tokens[2] if len(tokens) > 2 else "<missing data>")
            else:
                print("[ML] Unknown ML command")
            return True
        return False
    def help(self):
        return "ml train <data>, ml predict <input>, ml evaluate <data>"

class MobileExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "mobile":
            if len(tokens) < 2:
                print("[Mobile] Missing subcommand.")
                return True
            if tokens[1] == "build":
                print("[Mobile] Simulating mobile app build for platform:", tokens[2] if len(tokens) > 2 else "<missing platform>")
            elif tokens[1] == "deploy":
                print("[Mobile] Simulating mobile app deployment to:", tokens[2] if len(tokens) > 2 else "<missing device>")
            else:
                print("[Mobile] Unknown mobile command")
            return True
        return False
    def help(self):
        return "mobile build <platform>, mobile deploy <device>"

class GameExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "game":
            if len(tokens) < 2:
                print("[Game] Missing subcommand.")
                return True
            if tokens[1] == "start":
                print("[Game] Simulating game engine start")
            elif tokens[1] == "entity":
                print("[Game] Simulating entity creation:", " ".join(tokens[2:]))
            elif tokens[1] == "event":
                print("[Game] Simulating game event:", " ".join(tokens[2:]))
            else:
                print("[Game] Unknown game command")
            return True
        return False
    def help(self):
        return "game start, game entity <name>, game event <event>"

# --- Machine Code Generation ---
class CodeGenerator:
    def __init__(self):
        self.instructions = []
        self.labels = set()
        self.variables = {}
        self.var_offset = 0

    def emit(self, instr):
        self.instructions.append(instr)

    # --- Stack/Heap/Memory ---
    def generate_stack_push(self, value):
        self.emit(f"    ; stack push {value}")
        self.emit(f"    mov rax, {value}")
        self.emit(f"    push rax")

    def generate_stack_pop(self):
        self.emit("    ; stack pop")
        self.emit("    pop rax")

    def generate_heap_allocate(self, name, value):
        # Actually allocate in the Python heap
        heap.allocate(name, value)

    def generate_heap_delete(self, name):
        heap.delete(name)

    def generate_heap_dump(self):
        dump = heap.dump()
        self.emit(f"    ; heap dump: {dump}")

    # --- Arithmetic/Logic ---
    def generate_add(self):
        self.emit("    ; add")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    add rax, rbx")
        self.emit("    push rax")

    def generate_sub(self):
        self.emit("    ; sub")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    sub rbx, rax")
        self.emit("    push rbx")

    def generate_mul(self):
        self.emit("    ; mul")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    imul rax, rbx")
        self.emit("    push rax")

    def generate_div(self):
        self.emit("    ; div")
        self.emit("    pop rbx")
        self.emit("    pop rax")
        self.emit("    cqo")
        self.emit("    idiv rbx")
        self.emit("    push rax")

    def generate_neg(self):
        self.emit("    ; negate")
        self.emit("    pop rax")
        self.emit("    neg rax")
        self.emit("    push rax")

    def generate_mod(self):
        self.emit("    ; mod")
        self.emit("    pop rbx")
        self.emit("    pop rax")
        self.emit("    cqo")
        self.emit("    idiv rbx")
        self.emit("    push rdx")

    # --- Comparison/Conditionals ---
    def generate_cmp(self):
        self.emit("    ; compare")
        self.emit("    pop rax")
        self.emit("    pop rbx")
        self.emit("    cmp rbx, rax")

    def generate_jmp(self, label):
        self.emit(f"    jmp {label}")

    def generate_jz(self, label):
        self.emit("    pop rax")
        self.emit("    test rax, rax")
        self.emit(f"    jz {label}")

    def generate_jnz(self, label):
        self.emit("    pop rax")
        self.emit("    test rax, rax")
        self.emit(f"    jnz {label}")

    def generate_label(self, label):
        self.labels.add(label)
        self.emit(f"{label}:")

    def generate_call(self, label):
        self.emit(f"    call {label}")

    def generate_ret(self):
        self.emit("    ret")

    # --- Buffer/IO/Flow ---
    def generate_print(self):
        self.emit("    ; print (not implemented)")

    def generate_pause(self):
        self.emit("    ; pause (not implemented)")

    def generate_continue(self):
        self.emit("    ; continue (not implemented)")

    def generate_break(self):
        self.emit("    ; break (not implemented)")

    # --- Variable/Assignment ---
    def generate_var(self, name, value):
        variables.set(name, value)
        self.emit(f"    ; var {name} = {value}")

    def generate_mov(self, dest, src):
        # If dest is a variable, assign in the variable table
        if dest in variables.vars:
            variables.set(dest, src)
            self.emit(f"    ; mov {dest}, {src}")
        else:
            self.emit(f"    mov {dest}, {src}")

    # --- Error/Control ---
    def generate_error(self, msg):
        self.emit(f"    ; error: {msg}")

    def generate_nop(self):
        self.emit("    nop")

    # --- Output ---
    def output(self):
        return "\n".join([
            "section .text",
            "global _start",
            "_start:",
            *self.instructions,
            "    mov rax, 60",
            "    xor rdi, rdi",
            "    syscall"
        ])

    def output_bytes(self):
        return "\n".join(self.instructions)

class MachineCodeExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "compile":
            codegen = CodeGenerator()
            i = 1
            while i < len(tokens):
                t = tokens[i]
                if t == "stack" and i+2 < len(tokens) and tokens[i+1] == "push":
                    codegen.generate_stack_push(tokens[i+2])
                    i += 3
                elif t == "stack" and i+1 < len(tokens) and tokens[i+1] == "pop":
                    codegen.generate_stack_pop()
                    i += 2
                elif t == "heap" and i+2 < len(tokens) and tokens[i+1] == "allocate":
                    codegen.generate_heap_allocate(tokens[i+2], tokens[i+3] if i+3 < len(tokens) else "0")
                    i += 4
                elif t == "heap" and i+1 < len(tokens) and tokens[i+1] == "delete":
                    codegen.generate_heap_delete(tokens[i+2] if i+2 < len(tokens) else "")
                    i += 3
                elif t == "heap" and i+1 < len(tokens) and tokens[i+1] == "dump":
                    codegen.generate_heap_dump()
                    i += 2
                elif t == "add":
                    codegen.generate_add()
                    i += 1
                elif t == "sub":
                    codegen.generate_sub()
                    i += 1
                elif t == "mul":
                    codegen.generate_mul()
                    i += 1
                elif t == "div":
                    codegen.generate_div()
                    i += 1
                elif t == "neg":
                    codegen.generate_neg()
                    i += 1
                elif t == "mod":
                    codegen.generate_mod()
                    i += 1
                elif t == "cmp":
                    codegen.generate_cmp()
                    i += 1
                elif t == "jmp" and i+1 < len(tokens):
                    codegen.generate_jmp(tokens[i+1])
                    i += 2
                elif t == "jz" and i+1 < len(tokens):
                    codegen.generate_jz(tokens[i+1])
                    i += 2
                elif t == "jnz" and i+1 < len(tokens):
                    codegen.generate_jnz(tokens[i+1])
                    i += 2
                elif t == "label" and i+1 < len(tokens):
                    codegen.generate_label(tokens[i+1])
                    i += 2
                elif t == "call" and i+1 < len(tokens):
                    codegen.generate_call(tokens[i+1])
                    i += 2
                elif t == "ret":
                    codegen.generate_ret()
                    i += 1
                elif t == "var" and i+2 < len(tokens):
                    codegen.generate_var(tokens[i+1], tokens[i+2])
                    i += 3
                elif t == "mov" and i+2 < len(tokens):
                    codegen.generate_mov(tokens[i+1], tokens[i+2])
                    i += 3
                elif t == "print":
                    codegen.generate_print()
                    i += 1
                elif t == "pause":
                    codegen.generate_pause()
                    i += 1
                elif t == "continue":
                    codegen.generate_continue()
                    i += 1
                elif t == "break":
                    codegen.generate_break()
                    i += 1
                elif t == "nop":
                    codegen.generate_nop()
                    i += 1
                elif t == "error" and i+1 < len(tokens):
                    codegen.generate_error(tokens[i+1])
                    i += 2
                else:
                    i += 1

            print("\n[Generated x86-64 Assembly]:\n")
            asm = codegen.output()
            print(asm)
            # AOT/JIT omitted for brevity, see previous code for integration
            return True
        return False

    def help(self):
        return (
            "compile <commands...>   # Outputs x86-64 assembly for supported commands\n"
            "Supported: stack push/pop, heap allocate/delete/dump, add, sub, mul, div, neg, mod, cmp, jmp, jz, jnz, label, call, ret, var, mov, print, pause, continue, break, nop, error"
        )

# Register extensions
extensions = [
    WebExtension(),
    GUIExtension(),
    MLExtension(),
    MobileExtension(),
    GameExtension(),
    MachineCodeExtension(),
]

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        return

    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[{ext.__class__.__name__}] Error: {e}")
            return

    command = tokens[0]
    try:
        if command == "stack":
            if tokens[1] == "push":
                value = " ".join(tokens[2:])
                stack.push(value)
            elif tokens[1] == "pop":
                print("Popped:", stack.pop())
            elif tokens[1] == "peek":
                print("Top of stack:", stack.peek())
            elif tokens[1] == "clear":
                stack.clear()
            elif tokens[1] == "size":
                print("Stack size:", stack.size())
            else:
                print("[Stack] Unknown stack command")
        elif command == "heap":
            action = tokens[1]
            if action == "allocate":
                name = tokens[2]
                value = " ".join(tokens[3:])
                heap.allocate(name, value)
            elif action == "get":
                name = tokens[2]
                print(f"{name} =", heap.retrieve(name))
            elif action == "delete":
                heap.delete(tokens[2])
            elif action == "dump":
                print(heap.dump())
            elif action == "clear":
                heap.clear()
            elif action == "keys":
                print("Heap keys:", heap.keys())
            else:
                print("[Heap] Unknown heap command")
        elif command == "var":
            name = tokens[1]
            value = " ".join(tokens[2:])
            variables.set(name, value)
            variables.display()
        elif command == "getvar":
            name = tokens[1]
            print(f"{name} =", variables.get(name))
        elif command == "delvar":
            name = tokens[1]
            variables.delete(name)
            variables.display()
        elif command == "vars":
            print(variables.dump())
        elif command == "clearvars":
            variables.clear()
            variables.display()
        elif command == "stdlib":
            fn = tokens[1]
            args = [eval(arg) for arg in tokens[2:]]
            if hasattr(T, fn):
                result = getattr(T, fn)(*args)
                print(f"Result of {fn}:", result)
            else:
                print(f"Function {fn} not found in stdlib")
        else:
            print(f"Unknown command: {cmd}")
    except Exception as e:
        print(f"[Interpreter] Error: {e}")

        return True
        return False
       
    if len(tokens) < 2:
        print("[Error] Missing subcommand for 'stack'.")
    return

# ... [existing code above remains unchanged] ...

# --- Variable Table for Assignments ---
class VariableTable:
    def __init__(self):
        self.vars = {}
        self.lock = threading.Lock()

    def set(self, name, value):
        with self.lock:
            self.vars[name] = value

    def get(self, name):
        with self.lock:
            return self.vars.get(name, None)

    def delete(self, name):
        with self.lock:
            if name in self.vars:
                del self.vars[name]

    def clear(self):
        with self.lock:
            self.vars.clear()

    def dump(self):
        with self.lock:
            return dict(self.vars)

    def display(self):
        print("\n[VARIABLES]")
        for k, v in self.vars.items():
            print(f"{k} = {v}")
        print("-" * 20)

variables = VariableTable()

# --- Language: Extended Interpreter Commands ---
def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        print("[Error] Empty command.")
        return

    # Try extensions first
    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[{ext.__class__.__name__}] Error: {e}")
            return

    command = tokens[0]
    try:
        # Stack
        if command == "stack":
            if len(tokens) < 2:
                print("[Error] Missing subcommand for 'stack'.")
                return
            sub = tokens[1]
            if sub == "push":
                if len(tokens) < 3:
                    print("[Error] 'stack push' requires a value.")
                    return
                value = " ".join(tokens[2:])
                stack.push(value)
            elif sub == "pop":
                print("Popped:", stack.pop())
            elif sub == "peek":
                print("Top of stack:", stack.peek())
            elif sub == "clear":
                stack.clear()
            elif sub == "size":
                print("Stack size:", stack.size())
            else:
                print(f"[Error] Unknown stack subcommand: {sub}")

        # Heap
        elif command == "heap":
            if len(tokens) < 2:
                print("[Error] Missing subcommand for 'heap'.")
                return
            action = tokens[1]
            if action == "allocate":
                if len(tokens) < 4:
                    print("[Error] 'heap allocate' requires a name and value.")
                    return
                name = tokens[2]
                value = " ".join(tokens[3:])
                heap.allocate(name, value)
            elif action == "get":
                if len(tokens) < 3:
                    print("[Error] 'heap get' requires a name.")
                    return
                name = tokens[2]
                print(f"{name} =", heap.retrieve(name))
            elif action == "delete":
                if len(tokens) < 3:
                    print("[Error] 'heap delete' requires a name.")
                    return
                heap.delete(tokens[2])
            elif action == "dump":
                print(heap.dump())
            elif action == "clear":
                heap.clear()
            elif action == "keys":
                print("Heap keys:", heap.keys())
            else:
                print(f"[Error] Unknown heap subcommand: {action}")

        # Variables
        elif command == "var":
            if len(tokens) < 3:
                print("[Error] 'var' requires a name and value.")
                return
            name = tokens[1]
            value = " ".join(tokens[2:])
            variables.set(name, value)
            variables.display()
        elif command == "getvar":
            if len(tokens) < 2:
                print("[Error] 'getvar' requires a name.")
                return
            name = tokens[1]
            print(f"{name} =", variables.get(name))
        elif command == "delvar":
            if len(tokens) < 2:
                print("[Error] 'delvar' requires a name.")
                return
            name = tokens[1]
            variables.delete(name)
            variables.display()
        elif command == "vars":
            print(variables.dump())
        elif command == "clearvars":
            variables.clear()
            variables.display()

        # Conditionals
        elif command == "if":
            # Syntax: if <var> <operator> <value> then <command>
            if len(tokens) < 6 or tokens[4] != "then":
                print("[Error] Syntax: if <var> <operator> <value> then <command>")
                return
            var = variables.get(tokens[1])
            op = tokens[2]
            val = tokens[3]
            cond = False
            try:
                if op == "==":
                    cond = str(var) == val
                elif op == "!=":
                    cond = str(var) != val
                elif op == "<":
                    cond = float(var) < float(val)
                elif op == "<=":
                    cond = float(var) <= float(val)
                elif op == ">":
                    cond = float(var) > float(val)
                elif op == ">=":
                    cond = float(var) >= float(val)
                else:
                    print(f"[Error] Unknown operator: {op}")
                    return
            except Exception as e:
                print(f"[Error] Condition evaluation failed: {e}")
                return
            if cond:
                run_tempercore_command(" ".join(tokens[5:]))

        # Loops
        elif command == "while":
            # Syntax: while <var> <operator> <value> do <command>
            if len(tokens) < 6 or tokens[4] != "do":
                print("[Error] Syntax: while <var> <operator> <value> do <command>")
                return
            varname = tokens[1]
            op = tokens[2]
            val = tokens[3]
            body = " ".join(tokens[5:])
            while True:
                var = variables.get(varname)
                try:
                    if op == "==":
                        cond = str(var) == val
                    elif op == "!=":
                        cond = str(var) != val
                    elif op == "<":
                        cond = float(var) < float(val)
                    elif op == "<=":
                        cond = float(var) <= float(val)
                    elif op == ">":
                        cond = float(var) > float(val)
                    elif op == ">=":
                        cond = float(var) >= float(val)
                    else:
                        print(f"[Error] Unknown operator: {op}")
                        break
                except Exception as e:
                    print(f"[Error] Condition evaluation failed: {e}")
                    break
                if not cond:
                    break
                run_tempercore_command(body)

        # List/Array
        elif command == "list":
            # Syntax: list <name> [<item1> <item2> ...]
            if len(tokens) < 3:
                print("[Error] 'list' requires a name and at least one item.")
                return
            name = tokens[1]
            items = tokens[2:]
            variables.set(name, items)
            print(f"List {name} =", items)
        elif command == "append":
            # Syntax: append <listname> <item>
            if len(tokens) < 3:
                print("[Error] 'append' requires a list name and an item.")
                return
            name = tokens[1]
            item = tokens[2]
            lst = variables.get(name)
            if not isinstance(lst, list):
                print(f"[Error] {name} is not a list.")
                return
            lst.append(item)
            variables.set(name, lst)
            print(f"List {name} =", lst)
        elif command == "pop":
            # Syntax: pop <listname>
            if len(tokens) < 2:
                print("[Error] 'pop' requires a list name.")
                return
            name = tokens[1]
            lst = variables.get(name)
            if not isinstance(lst, list):
                print(f"[Error] {name} is not a list.")
                return
            if not lst:
                print(f"[Error] {name} is empty.")
                return
            val = lst.pop()
            variables.set(name, lst)
            print(f"Popped {val} from {name}. List now: {lst}")

        # Math
        elif command == "add":
            # Syntax: add <var1> <var2> <resultvar>
            if len(tokens) < 4:
                print("[Error] 'add' requires two variables and a result variable.")
                return
            v1 = float(variables.get(tokens[1]))
            v2 = float(variables.get(tokens[2]))
            variables.set(tokens[3], v1 + v2)
            print(f"{tokens[3]} = {v1 + v2}")
        elif command == "sub":
            if len(tokens) < 4:
                print("[Error] 'sub' requires two variables and a result variable.")
                return
            v1 = float(variables.get(tokens[1]))
            v2 = float(variables.get(tokens[2]))
            variables.set(tokens[3], v1 - v2)
            print(f"{tokens[3]} = {v1 - v2}")
        elif command == "mul":
            if len(tokens) < 4:
                print("[Error] 'mul' requires two variables and a result variable.")
                return
            v1 = float(variables.get(tokens[1]))
            v2 = float(variables.get(tokens[2]))
            variables.set(tokens[3], v1 * v2)
            print(f"{tokens[3]} = {v1 * v2}")
        elif command == "div":
            if len(tokens) < 4:
                print("[Error] 'div' requires two variables and a result variable.")
                return
            v1 = float(variables.get(tokens[1]))
            v2 = float(variables.get(tokens[2]))
            if v2 == 0:
                print("[Error] Division by zero.")
                return
            variables.set(tokens[3], v1 / v2)
            print(f"{tokens[3]} = {v1 / v2}")

        # String
        elif command == "concat":
            # Syntax: concat <var1> <var2> <resultvar>
            if len(tokens) < 4:
                print("[Error] 'concat' requires two variables and a result variable.")
                return
            v1 = str(variables.get(tokens[1]))
            v2 = str(variables.get(tokens[2]))
            variables.set(tokens[3], v1 + v2)
            print(f"{tokens[3]} = {v1 + v2}")

        # Print
        elif command == "print":
            # Syntax: print <var>
            if len(tokens) < 2:
                print("[Error] 'print' requires a variable name or value.")
                return
            val = variables.get(tokens[1])
            if val is None:
                val = tokens[1]
            print(val)

        # Control
        elif command == "break":
            print("[Break] (no-op in top-level)")
        elif command == "continue":
            print("[Continue] (no-op in top-level)")
        elif command == "pause":
            input("[Pause] Press Enter to continue...")

        # Utility
        elif command == "help":
            print("Supported commands: stack, heap, var, getvar, delvar, vars, clearvars, if, while, list, append, pop, add, sub, mul, div, concat, print, break, continue, pause, stdlib")
        elif command == "exit" or command == "quit":
            print("Exiting interpreter.")
            exit(0)

        # Stdlib
        elif command == "stdlib":
            if len(tokens) < 2:
                print("[Error] 'stdlib' requires a function name.")
                return
            fn = tokens[1]
            args = [eval(arg) for arg in tokens[2:]]
            if hasattr(T, fn):
                result = getattr(T, fn)(*args)
                print(f"Result of {fn}:", result)
            else:
                print(f"Function {fn} not found in stdlib")

        else:
            print(f"[Error] Unknown command: {command}")
    except Exception as e:
        print(f"[Interpreter Error] {type(e).__name__}: {e}")

# ... [rest of the file, including extensions and code generator, remains unchanged] ...

# --- Stack Implementation ---
class Stack:
    def __init__(self):
        self.stack = []
        self.lock = threading.Lock()
    def push(self, value):
        with self.lock:
            self.stack.append(value)
            self.display()
    def pop(self):
        with self.lock:
            if not self.stack:
                print("[Stack] Underflow error: stack is empty.")
                return None
            value = self.stack.pop()
            self.display()
            return value
    def peek(self):
        with self.lock:
            if not self.stack:
                print("[Stack] Underflow error: stack is empty.")
                return None
            return self.stack[-1]

        def clear(self):
            with self.lock:
                self.stack.clear()
            self.display()

            def size(self):
                with self.lock:
                    return len(self.stack)
                def display(self):
                    print("\n[STACK]")

                    for i, v in enumerate(reversed(self.stack)):
                        print(f"{i}: {v}")
                        print("-" * 20)

import threading
import socket
import http.server
import socketserver
import requests
import tkinter as tk
import queue
import time
import ctypes
import sys
from stdlib import TempercoreStdLib as T

# --- Stack Implementation (unchanged) ---
class Stack:
    def __init__(self):
        self.stack = []
        self.lock = threading.Lock()

    def push(self, val):
        with self.lock:
            self.stack.append(val)
            self.display()

    def pop(self):
        with self.lock:
            val = self.stack.pop() if self.stack else None
            self.display()
            return val

    def peek(self):
        with self.lock:
            return self.stack[-1] if self.stack else None

    def clear(self):
        with self.lock:
            self.stack.clear()
            self.display()

    def size(self):
        with self.lock:
            return len(self.stack)

    def display(self):
        print("\n[STACK]")
        for i, item in enumerate(reversed(self.stack)):
            print(f"{len(self.stack) - i}: {item}")
        print("-" * 20)

# --- Heap with Memory Optimization and Concurrency ---
class Heap:
    def __init__(self, max_size=1024 * 1024 * 10):  # 10MB default
        self.heap = {}
        self.lock = threading.RLock()
        self.max_size = max_size
        self.used = 0
        self.alloc_map = {}  # name: size

    def allocate(self, name, value):
        with self.lock:
            size = sys.getsizeof(value)
            if self.used + size > self.max_size:
                print(f"[Heap] Allocation failed: Not enough memory for '{name}' ({size} bytes).")
                return
            if name in self.heap:
                self.used -= self.alloc_map[name]
            self.heap[name] = value
            self.alloc_map[name] = size
            self.used += size
            self.display()

    def retrieve(self, name):
        with self.lock:
            return self.heap.get(name, None)

    def delete(self, name):
        with self.lock:
            if name in self.heap:
                self.used -= self.alloc_map[name]
                del self.heap[name]
                del self.alloc_map[name]
                self.display()

    def clear(self):
        with self.lock:
            self.heap.clear()
            self.alloc_map.clear()
            self.used = 0
            self.display()

    def keys(self):
        with self.lock:
            return list(self.heap.keys())

    def dump(self):
        with self.lock:
            return dict(self.heap)

    def memory_usage(self):
        with self.lock:
            return self.used, self.max_size

    def display(self):
        print("\n[HEAP]")
        for k, v in self.heap.items():
            print(f"{k} => {v} ({self.alloc_map[k]} bytes)")
        print(f"Used: {self.used} / {self.max_size} bytes")
        print("-" * 20)

stack = Stack()
heap = Heap()

# --- Extension System ---
class Extension:
    def handle(self, tokens):
        raise NotImplementedError

    def help(self):
        return ""

# --- WebExtension: Real Networking ---
class WebExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "web":
            if len(tokens) < 2:
                print("[Web] Missing subcommand.")
                return True
            if tokens[1] == "serve":
                port = int(tokens[2]) if len(tokens) > 2 else 8080
                handler = http.server.SimpleHTTPRequestHandler
                def serve():
                    with socketserver.TCPServer(("", port), handler) as httpd:
                        print(f"[Web] Serving HTTP on port {port} (Ctrl+C to stop)...")
                        try:
                            httpd.serve_forever()
                        except KeyboardInterrupt:
                            print("[Web] Server stopped.")
                threading.Thread(target=serve, daemon=True).start()
            elif tokens[1] == "request":
                if len(tokens) < 3:
                    print("[Web] 'request' requires a URL.")
                    return True
                url = tokens[2]
                try:
                    resp = requests.get(url)
                    print(f"[Web] GET {url} -> {resp.status_code}\n{resp.text[:200]}...")
                except Exception as e:
                    print(f"[Web] Request error: {e}")
            elif tokens[1] == "socket":
                if len(tokens) < 3:
                    print("[Web] 'socket' requires a host:port.")
                    return True
                host, port = tokens[2].split(":")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((host, int(port)))
                    print(f"[Web] Connected to {host}:{port}")
                    s.close()
                except Exception as e:
                    print(f"[Web] Socket error: {e}")
            else:
                print("[Web] Unknown web command")
            return True
        return False
    def help(self):
        return "web serve <port>, web request <url>, web socket <host:port>"

# --- GUIExtension: Real Tkinter UI ---
class GUIExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "gui":
            if len(tokens) < 2:
                print("[GUI] Missing subcommand.")
                return True
            if tokens[1] == "window":
                title = " ".join(tokens[2:]) if len(tokens) > 2 else "Tempercore Window"
                def show_window():
                    root = tk.Tk()
                    root.title(title)
                    tk.Label(root, text=title).pack()
                    root.mainloop()
                threading.Thread(target=show_window, daemon=True).start()
            elif tokens[1] == "button":
                label = " ".join(tokens[2:]) if len(tokens) > 2 else "Button"
                def show_button():
                    root = tk.Tk()
                    tk.Button(root, text=label, command=root.destroy).pack()
                    root.mainloop()
                threading.Thread(target=show_button, daemon=True).start()
            elif tokens[1] == "label":
                text = " ".join(tokens[2:]) if len(tokens) > 2 else "Label"
                def show_label():
                    root = tk.Tk()
                    tk.Label(root, text=text).pack()
                    root.mainloop()
                threading.Thread(target=show_label, daemon=True).start()
            else:
                print("[GUI] Unknown GUI command")
            return True
        return False
    def help(self):
        return "gui window <title>, gui button <label>, gui label <text>"

# --- MLExtension: Real ML with scikit-learn (if available) ---
try:
    from sklearn.linear_model import LinearRegression
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class MLExtension(Extension):
    def __init__(self):
        self.models = {}

    def handle(self, tokens):
        if tokens[0] == "ml":
            if not SKLEARN_AVAILABLE:
                print("[ML] scikit-learn not available. Install with 'pip install scikit-learn numpy'.")
                return True
            if len(tokens) < 2:
                print("[ML] Missing subcommand.")
                return True
            if tokens[1] == "train":
                # ml train <modelname> <x1,x2,...> <y1,y2,...>
                if len(tokens) < 5:
                    print("[ML] Usage: ml train <modelname> <x1,x2,...> <y1,y2,...>")
                    return True
                name = tokens[2]
                X = np.array([[float(x)] for x in tokens[3].split(",")])
                y = np.array([float(y) for y in tokens[4].split(",")])
                model = LinearRegression()
                model.fit(X, y)
                self.models[name] = model
                print(f"[ML] Trained model '{name}'")
            elif tokens[1] == "predict":
                # ml predict <modelname> <x>
                if len(tokens) < 4:
                    print("[ML] Usage: ml predict <modelname> <x>")
                    return True
                name = tokens[2]
                x = float(tokens[3])
                model = self.models.get(name)
                if not model:
                    print(f"[ML] Model '{name}' not found.")
                    return True
                pred = model.predict(np.array([[x]]))
                print(f"[ML] Prediction: {pred[0]}")
            elif tokens[1] == "evaluate":
                # ml evaluate <modelname> <x1,x2,...> <y1,y2,...>
                if len(tokens) < 5:
                    print("[ML] Usage: ml evaluate <modelname> <x1,x2,...> <y1,y2,...>")
                    return True
                name = tokens[2]
                X = np.array([[float(x)] for x in tokens[3].split(",")])
                y = np.array([float(y) for y in tokens[4].split(",")])
                model = self.models.get(name)
                if not model:
                    print(f"[ML] Model '{name}' not found.")
                    return True
                score = model.score(X, y)
                print(f"[ML] R^2 score: {score}")
            else:
                print("[ML] Unknown ML command")
            return True
        return False
    def help(self):
        return "ml train <model> <x1,x2,...> <y1,y2,...>, ml predict <model> <x>, ml evaluate <model> <x1,x2,...> <y1,y2,...>"

# --- MobileExtension and GameExtension: Placeholders for real actions ---
class MobileExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "mobile":
            if len(tokens) < 2:
                print("[Mobile] Missing subcommand.")
                return True
            if tokens[1] == "build":
                print("[Mobile] (Placeholder) Real mobile build would require platform SDK integration.")
            elif tokens[1] == "deploy":
                print("[Mobile] (Placeholder) Real deployment would require device connection.")
            else:
                print("[Mobile] Unknown mobile command")
            return True
        return False
    def help(self):
        return "mobile build <platform>, mobile deploy <device>"

class GameExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "game":
            if len(tokens) < 2:
                print("[Game] Missing subcommand.")
                return True
            if tokens[1] == "start":
                print("[Game] (Placeholder) Real game engine integration not implemented.")
            elif tokens[1] == "entity":
                print("[Game] (Placeholder) Real entity creation not implemented.")
            elif tokens[1] == "event":
                print("[Game] (Placeholder) Real event system not implemented.")
            else:
                print("[Game] Unknown game command")
            return True
        return False
    def help(self):
        return "game start, game entity <name>, game event <event>"

# --- Register extensions ---
extensions = [
    WebExtension(),
    GUIExtension(),
    MLExtension(),
    MobileExtension(),
    GameExtension(),
    # ... (other extensions, e.g., MachineCodeExtension) ...
]

# --- Improved Error Handling in Interpreter ---
def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        print("[Error] Empty command.")
        return

    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[Extension Error] {ext.__class__.__name__}: {type(e).__name__}: {e}")
            return

    command = tokens[0]
    try:
        # ... (existing interpreter command handling) ...
        print(f"[Error] Unknown command: {command}")
    except Exception as e:
        import traceback
        print(f"[Interpreter Error] {type(e).__name__}: {e}")
        traceback.print_exc()

        import threading
import asyncio
import sys
import ctypes
import numpy as np

# --- SIMD/AVX2 Vectorized Math ---
def avx2_vector_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Add two float32 arrays using AVX2 (via numpy, which uses BLAS/SIMD under the hood)."""
    assert a.dtype == np.float32 and b.dtype == np.float32
    return np.add(a, b)

# --- Memory Pool for Heap ---
class MemoryPool:
    def __init__(self, block_size=4096, pool_size=1024*1024*10):
        self.block_size = block_size
        self.pool_size = pool_size
        self.pool = bytearray(pool_size)
        self.free_blocks = list(range(0, pool_size, block_size))
        self.lock = threading.Lock()
        self.alloc_map = {}

    def allocate(self, name, size):
        with self.lock:
            if not self.free_blocks:
                raise MemoryError("Out of memory in pool")
            block = self.free_blocks.pop()
            self.alloc_map[name] = (block, size)
            return memoryview(self.pool)[block:block+size]

    def free(self, name):
        with self.lock:
            if name in self.alloc_map:
                block, _ = self.alloc_map.pop(name)
                self.free_blocks.append(block)

# --- Async Heap with Memory Pool ---
class AsyncHeap:
    def __init__(self, pool: MemoryPool):
        self.pool = pool
        self.objects = {}
        self.lock = asyncio.Lock()

    async def allocate(self, name, value):
        async with self.lock:
            size = sys.getsizeof(value)
            buf = self.pool.allocate(name, size)
            buf[:len(bytes(str(value), 'utf-8'))] = bytes(str(value), 'utf-8')
            self.objects[name] = buf

    async def retrieve(self, name):
        async with self.lock:
            buf = self.objects.get(name)
            if buf is not None:
                return bytes(buf).decode('utf-8', errors='replace')
            return None

    async def delete(self, name):
        async with self.lock:
            if name in self.objects:
                self.pool.free(name)
                del self.objects[name]

# --- Register Allocator for CodeGen ---
class RegisterAllocator:
    def __init__(self):
        self.registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']
        self.free = set(self.registers)
        self.in_use = set()

    def alloc(self):
        if not self.free:
            raise RuntimeError("No free registers")
        reg = self.free.pop()
        self.in_use.add(reg)
        return reg

    def free_reg(self, reg):
        if reg in self.in_use:
            self.in_use.remove(reg)
            self.free.add(reg)

# --- Optimized Code Generator with SIMD and Register Allocation ---
class CodeGenerator:
    def __init__(self):
        self.instructions = []
        self.reg_alloc = RegisterAllocator()

    def emit(self, instr):
        self.instructions.append(instr)

    def generate_vector_add(self, dest, src1, src2):
        # AVX2: vaddps ymm_dest, ymm_src1, ymm_src2
        self.emit(f"    vaddps {dest}, {src1}, {src2}")

    def generate_stack_push(self, value):
        reg = self.reg_alloc.alloc()
        self.emit(f"    mov {reg}, {value}")
        self.emit(f"    push {reg}")
        self.reg_alloc.free_reg(reg)

    def generate_stack_pop(self):
        reg = self.reg_alloc.alloc()
        self.emit(f"    pop {reg}")
        self.reg_alloc.free_reg(reg)

    def generate_add(self):
        reg1 = self.reg_alloc.alloc()
        reg2 = self.reg_alloc.alloc()
        self.emit(f"    pop {reg1}")
        self.emit(f"    pop {reg2}")
        self.emit(f"    add {reg1}, {reg2}")
        self.emit(f"    push {reg1}")
        self.reg_alloc.free_reg(reg1)
        self.reg_alloc.free_reg(reg2)

    def output(self):
        return "\n".join([
            "section .text",
            "global _start",
            "_start:",
            *self.instructions,
            "    mov rax, 60",
            "    xor rdi, rdi",
            "    syscall"
        ])

# --- Hardware Feature Detection ---
def detect_avx2():
    import subprocess
    if sys.platform == "linux":
        try:
            out = subprocess.check_output("lscpu", shell=True).decode()
            return "avx2" in out
        except Exception:
            return False
    return False

# --- Example Usage ---
if __name__ == "__main__":
    # SIMD vector add
    a = np.ones(8, dtype=np.float32)
    b = np.ones(8, dtype=np.float32)
    c = avx2_vector_add(a, b)
    print("SIMD add result:", c)

    # Memory pool and async heap
    pool = MemoryPool()
    heap = AsyncHeap(pool)
    async def heap_demo():
        await heap.allocate("foo", "bar")
        print("Heap retrieve:", await heap.retrieve("foo"))
        await heap.delete("foo")
    asyncio.run(heap_demo())

    # Code generation
    codegen = CodeGenerator()
    if detect_avx2():
        codegen.generate_vector_add("ymm0", "ymm1", "ymm2")
    codegen.generate_stack_push(42)
    codegen.generate_stack_pop()
    codegen.generate_add()
    print("\n[Optimized Assembly]:\n", codegen.output())

    import numpy as np
import multiprocessing as mp
import ctypes
import sys
import os
import platform
from llvmlite import ir, binding

# --- LLVM JIT Backend with AVX-512/SVE Hooks ---
class LLVMJIT:
    def __init__(self):
        binding.initialize()
        binding.initialize_native_target()
        binding.initialize_native_asmprinter()
        self.target = binding.Target.from_default_triple()
        self.target_machine = self.target.create_target_machine()
        self.module = ir.Module(name="jit_module")
        self.engine = self.create_execution_engine()

    def create_execution_engine(self):
        backing_mod = binding.parse_assembly("")
        engine = binding.create_mcjit_compiler(backing_mod, self.target_machine)
        return engine

    def compile_ir(self, llvm_ir):
        mod = binding.parse_assembly(llvm_ir)
        mod.verify()
        self.engine.add_module(mod)
        self.engine.finalize_object()
        self.engine.run_static_constructors()
        return mod

    def add_vector_add_function(self, vector_width=8):
        # AVX-512: 16 floats, AVX2: 8 floats, SVE: variable
        float_ty = ir.FloatType()
        vec_ty = ir.VectorType(float_ty, vector_width)
        func_ty = ir.FunctionType(vec_ty, [vec_ty, vec_ty])
        func = ir.Function(self.module, func_ty, name="vec_add")
        a, b = func.args
        block = func.append_basic_block(name="entry")
        builder = ir.IRBuilder(block)
        result = builder.fadd(a, b, name="addtmp")
        builder.ret(result)
        return func

    def run_vector_add(self, a, b):
        llvm_ir = str(self.module)
        self.compile_ir(llvm_ir)
        func_ptr = self.engine.get_function_address("vec_add")
        cfunc = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(func_ptr)
        # This is a stub: in practice, you'd use ctypes arrays and pass pointers
        return cfunc(a.ctypes.data, b.ctypes.data)

# --- Profile-Guided Optimization (PGO) Stub ---
class Profiler:
    def __init__(self):
        self.counts = {}

    def profile(self, func):
        def wrapper(*args, **kwargs):
            name = func.__name__
            self.counts[name] = self.counts.get(name, 0) + 1
            return func(*args, **kwargs)
        return wrapper

    def report(self):
        print("[PGO] Function call counts:", self.counts)

profiler = Profiler()

# --- Custom Memory Allocator: Pool, Stack, Region ---
class SupremeAllocator:
    def __init__(self, pool_size=1024*1024*10):
        self.pool = bytearray(pool_size)
        self.free = [(0, pool_size)]
        self.allocs = {}

    def allocate(self, name, size):
        for i, (start, length) in enumerate(self.free):
            if length >= size:
                self.allocs[name] = (start, size)
                if length == size:
                    self.free.pop(i)
                else:
                    self.free[i] = (start + size, length - size)
                return memoryview(self.pool)[start:start+size]
        raise MemoryError("Out of memory")

    def free_alloc(self, name):
        if name in self.allocs:
            start, size = self.allocs.pop(name)
            self.free.append((start, size))
            self.free = sorted(self.free)

# --- Runtime CPU Feature Detection and Specialization ---
def detect_cpu_features():
    features = {
        "avx512": False,
        "avx2": False,
        "sve": False,
        "gpu": False
    }
    if sys.platform == "linux":
        try:
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read()
            features["avx512"] = "avx512" in cpuinfo
            features["avx2"] = "avx2" in cpuinfo
        except Exception:
            pass
    # SVE detection stub (for ARM)
    if "aarch64" in platform.machine():
        features["sve"] = True  # Assume SVE for demo
    # GPU detection stub
    try:
        import cupy
        features["gpu"] = True
    except ImportError:
        pass
    return features

# --- SIMD/AVX-512/SVE Vectorized Math ---
def supreme_vector_add(a: np.ndarray, b: np.ndarray, features):
    if features["gpu"]:
        import cupy as cp
        a_gpu = cp.asarray(a)
        b_gpu = cp.asarray(b)
        return cp.asnumpy(a_gpu + b_gpu)
    elif features["avx512"]:
        # AVX-512: 16-wide float32
        return np.add(a, b)  # numpy uses MKL/BLAS if available
    elif features["avx2"]:
        return np.add(a, b)
    elif features["sve"]:
        return np.add(a, b)
    else:
        return a + b

# --- Parallelism: Multiprocessing, SIMD, GPU ---
def parallel_sum(arrays, features):
    if features["gpu"]:
        import cupy as cp
        arrays_gpu = [cp.asarray(a) for a in arrays]
        return cp.asnumpy(sum(arrays_gpu))
    else:
        with mp.Pool(mp.cpu_count()) as pool:
            results = pool.map(np.sum, arrays)
        return sum(results)

# --- Example Usage ---
if __name__ == "__main__":
    features = detect_cpu_features()
    print("[CPU Features]", features)

    # LLVM JIT with AVX-512/AVX2/SVE
    jit = LLVMJIT()
    jit.add_vector_add_function(vector_width=16 if features["avx512"] else 8)
    a = np.ones(16 if features["avx512"] else 8, dtype=np.float32)
    b = np.ones_like(a)
    # Note: jit.run_vector_add is a stub; real use would require more ctypes glue

    # Profiled vector add
    @profiler.profile
    def profiled_add(a, b):
        return supreme_vector_add(a, b, features)
    c = profiled_add(a, b)
    print("Supreme SIMD add result:", c)
    profiler.report()

    # Custom memory allocator
    allocator = SupremeAllocator()
    buf = allocator.allocate("foo", 128)
    buf[:3] = b"bar"
    print("Custom allocator buffer:", bytes(buf[:3]))
    allocator.free_alloc("foo")

    # Parallel sum
    arrays = [np.arange(1000000, dtype=np.float32) for _ in range(8)]
    total = parallel_sum(arrays, features)
    print("Parallel sum result:", total)

    import sys
import os
import platform
import numpy as np
import multiprocessing as mp
import ctypes
import asyncio

# --- LLVM JIT Backend (llvmlite) ---
try:
    from llvmlite import ir, binding
    LLVM_AVAILABLE = True
except ImportError:
    LLVM_AVAILABLE = False

class LLVMJIT:
    def __init__(self):
        if not LLVM_AVAILABLE:
            raise ImportError("llvmlite is required for LLVM JIT support.")
        binding.initialize()
        binding.initialize_native_target()
        binding.initialize_native_asmprinter()
        self.target = binding.Target.from_default_triple()
        self.target_machine = self.target.create_target_machine()
        self.module = ir.Module(name="jit_module")
        self.engine = self.create_execution_engine()

    def create_execution_engine(self):
        backing_mod = binding.parse_assembly("")
        engine = binding.create_mcjit_compiler(backing_mod, self.target_machine)
        return engine

    def compile_ir(self, llvm_ir):
        mod = binding.parse_assembly(llvm_ir)
        mod.verify()
        self.engine.add_module(mod)
        self.engine.finalize_object()
        self.engine.run_static_constructors()
        return mod

    def add_vector_add_function(self, vector_width=8):
        float_ty = ir.FloatType()
        vec_ty = ir.VectorType(float_ty, vector_width)
        func_ty = ir.FunctionType(vec_ty, [vec_ty, vec_ty])
        func = ir.Function(self.module, func_ty, name="vec_add")
        a, b = func.args
        block = func.append_basic_block(name="entry")
        builder = ir.IRBuilder(block)
        result = builder.fadd(a, b, name="addtmp")
        builder.ret(result)
        return func

    def run_vector_add(self, a, b):
        llvm_ir = str(self.module)
        self.compile_ir(llvm_ir)
        func_ptr = self.engine.get_function_address("vec_add")
        # This is a stub: in practice, you'd use ctypes arrays and pass pointers
        return func_ptr

# --- PGO (Profile-Guided Optimization) Stub ---
class Profiler:
    def __init__(self):
        self.counts = {}

    def profile(self, func):
        def wrapper(*args, **kwargs):
            name = func.__name__
            self.counts[name] = self.counts.get(name, 0) + 1
            return func(*args, **kwargs)
        return wrapper

    def report(self):
        print("[PGO] Function call counts:", self.counts)

profiler = Profiler()

# --- Custom Memory Allocator: Pool, Stack, Region ---
class SupremeAllocator:
    def __init__(self, pool_size=1024*1024*10):
        self.pool = bytearray(pool_size)
        self.free = [(0, pool_size)]
        self.allocs = {}

    def allocate(self, name, size):
        for i, (start, length) in enumerate(self.free):
            if length >= size:
                self.allocs[name] = (start, size)
                if length == size:
                    self.free.pop(i)
                else:
                    self.free[i] = (start + size, length - size)
                return memoryview(self.pool)[start:start+size]
        raise MemoryError("Out of memory")

    def free_alloc(self, name):
        if name in self.allocs:
            start, size = self.allocs.pop(name)
            self.free.append((start, size))
            self.free = sorted(self.free)

# --- Runtime CPU Feature Detection and Specialization ---
def detect_cpu_features():
    features = {
        "avx512": False,
        "avx2": False,
        "sve": False,
        "gpu": False
    }
    if sys.platform == "linux":
        try:
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read()
            features["avx512"] = "avx512" in cpuinfo
            features["avx2"] = "avx2" in cpuinfo
        except Exception:
            pass
    # SVE detection stub (for ARM)
    if "aarch64" in platform.machine():
        features["sve"] = True  # Assume SVE for demo
    # GPU detection stub
    try:
        import cupy
        features["gpu"] = True
    except ImportError:
        pass
    return features

# --- SIMD/AVX-512/SVE Vectorized Math ---
def supreme_vector_add(a: np.ndarray, b: np.ndarray, features):
    if features["gpu"]:
        import cupy as cp
        a_gpu = cp.asarray(a)
        b_gpu = cp.asarray(b)
        return cp.asnumpy(a_gpu + b_gpu)
    elif features["avx512"]:
        return np.add(a, b)  # numpy uses MKL/BLAS if available
    elif features["avx2"]:
        return np.add(a, b)
    elif features["sve"]:
        return np.add(a, b)
    else:
        return a + b

# --- Parallelism: Multiprocessing, SIMD, GPU ---
def parallel_sum(arrays, features):
    if features["gpu"]:
        import cupy as cp
        arrays_gpu = [cp.asarray(a) for a in arrays]
        return cp.asnumpy(sum(arrays_gpu))
    else:
        with mp.Pool(mp.cpu_count()) as pool:
            results = pool.map(np.sum, arrays)
        return sum(results)

# --- Example Usage ---
if __name__ == "__main__":
    features = detect_cpu_features()
    print("[CPU Features]", features)

    # LLVM JIT with AVX-512/AVX2/SVE
    if LLVM_AVAILABLE:
        jit = LLVMJIT()
        jit.add_vector_add_function(vector_width=16 if features["avx512"] else 8)
        a = np.ones(16 if features["avx512"] else 8, dtype=np.float32)
        b = np.ones_like(a)
        # Note: jit.run_vector_add is a stub; real use would require more ctypes glue

    # Profiled vector add
    @profiler.profile
    def profiled_add(a, b):
        return supreme_vector_add(a, b, features)
    c = profiled_add(a, b)
    print("Supreme SIMD add result:", c)
    profiler.report()

    # Custom memory allocator
    allocator = SupremeAllocator()
    buf = allocator.allocate("foo", 128)
    buf[:3] = b"bar"
    print("Custom allocator buffer:", bytes(buf[:3]))
    allocator.free_alloc("foo")

    # Parallel sum
    arrays = [np.arange(1000000, dtype=np.float32) for _ in range(8)]
    total = parallel_sum(arrays, features)
    print("Parallel sum result:", total)

from llvmlite import ir, binding

class LLVMJIT:
    # ... (existing __init__ and methods) ...

    def add_vector_mul_function(self, vector_width=8):
        float_ty = ir.FloatType()
        vec_ty = ir.VectorType(float_ty, vector_width)
        func_ty = ir.FunctionType(vec_ty, [vec_ty, vec_ty])
        func = ir.Function(self.module, func_ty, name="vec_mul")
        a, b = func.args
        block = func.append_basic_block(name="entry")
        builder = ir.IRBuilder(block)
        result = builder.fmul(a, b, name="multmp")
        builder.ret(result)
        return func

    def add_fma_function(self, vector_width=8):
        float_ty = ir.FloatType()
        vec_ty = ir.VectorType(float_ty, vector_width)
        func_ty = ir.FunctionType(vec_ty, [vec_ty, vec_ty, vec_ty])
        func = ir.Function(self.module, func_ty, name="vec_fma")
        a, b, c = func.args
        block = func.append_basic_block(name="entry")
        builder = ir.IRBuilder(block)
        # Fused multiply-add: (a * b) + c
        result = builder.fadd(builder.fmul(a, b), c, name="fmatmp")
        builder.ret(result)
        return func

    # Add more outrageously optimized vectorized/JIT functions as needed

# Usage in your interpreter:
if __name__ == "__main__":
    features = detect_cpu_features()
    if LLVM_AVAILABLE:
        jit = LLVMJIT()
        jit.add_vector_add_function(vector_width=16 if features["avx512"] else 8)
        jit.add_vector_mul_function(vector_width=16 if features["avx512"] else 8)
        jit.add_fma_function(vector_width=16 if features["avx512"] else 8)
        # ... compile and run as needed ...

class SIMDExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "simd":
            if tokens[1] == "add":
                # simd add <var1> <var2> <resultvar>
                a = np.array(variables.get(tokens[2]), dtype=np.float32)
                b = np.array(variables.get(tokens[3]), dtype=np.float32)
                result = supreme_vector_add(a, b, features)
                variables.set(tokens[4], result.tolist())
                print(f"{tokens[4]} =", result)
                return True
            # ... more SIMD ops ...
        return False

    import numpy as np
import multiprocessing as mp
import asyncio
import time

# Assume SupremeAllocator, supreme_vector_add, parallel_sum, detect_cpu_features, variables, and extensions are defined

supreme_allocator = SupremeAllocator()
features = detect_cpu_features()

def _ensure_list(var):
    val = variables.get(var)
    if not isinstance(val, list):
        raise ValueError(f"Variable '{var}' is not a list/array.")
    return val

def _ensure_array(val, dtype=np.float32):
    arr = np.array(val, dtype=dtype)
    if arr.ndim == 0:
        arr = arr.reshape(1)
    return arr

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        print("[Error] Empty command.")
        return

    # Try extensions first
    for ext in extensions:
        try:
            if ext.handle(tokens):
                return
        except Exception as e:
            print(f"[Extension Error] {ext.__class__.__name__}: {type(e).__name__}: {e}")
            return

    command = tokens[0]
    try:
        # --- SIMD Vector Add ---
        if command == "vector_add":
            # vector_add <var1> <var2> <resultvar>
            if len(tokens) != 4:
                print("[Error] Usage: vector_add <var1> <var2> <resultvar>")
                return
            a = _ensure_array(variables.get(tokens[1]))
            b = _ensure_array(variables.get(tokens[2]))
            if a.shape != b.shape:
                print("[Error] Arrays must have the same shape.")
                return
            t0 = time.perf_counter()
            result = supreme_vector_add(a, b, features)
            t1 = time.perf_counter()
            variables.set(tokens[3], result.tolist())
            print(f"{tokens[3]} = {result} [SIMD add in {t1-t0:.6f}s]")

        # --- SIMD Vector Multiply ---
        elif command == "vector_mul":
            # vector_mul <var1> <var2> <resultvar>
            if len(tokens) != 4:
                print("[Error] Usage: vector_mul <var1> <var2> <resultvar>")
                return
            a = _ensure_array(variables.get(tokens[1]))
            b = _ensure_array(variables.get(tokens[2]))
            if a.shape != b.shape:
                print("[Error] Arrays must have the same shape.")
                return
            t0 = time.perf_counter()
            result = np.multiply(a, b)
            t1 = time.perf_counter()
            variables.set(tokens[3], result.tolist())
            print(f"{tokens[3]} = {result} [SIMD mul in {t1-t0:.6f}s]")

        # --- SIMD Fused Multiply-Add (FMA) ---
        elif command == "vector_fma":
            # vector_fma <var1> <var2> <var3> <resultvar>
            if len(tokens) != 5:
                print("[Error] Usage: vector_fma <var1> <var2> <var3> <resultvar>")
                return
            a = _ensure_array(variables.get(tokens[1]))
            b = _ensure_array(variables.get(tokens[2]))
            c = _ensure_array(variables.get(tokens[3]))
            if not (a.shape == b.shape == c.shape):
                print("[Error] All arrays must have the same shape.")
                return
            t0 = time.perf_counter()
            result = np.add(np.multiply(a, b), c)
            t1 = time.perf_counter()
            variables.set(tokens[4], result.tolist())
            print(f"{tokens[4]} = {result} [SIMD FMA in {t1-t0:.6f}s]")

        # --- Parallel Sum ---
        elif command == "parallel_sum":
            # parallel_sum <listvar> <resultvar>
            if len(tokens) != 3:
                print("[Error] Usage: parallel_sum <listvar> <resultvar>")
                return
            arrays = [_ensure_array(x) for x in _ensure_list(tokens[1])]
            t0 = time.perf_counter()
            result = parallel_sum(arrays, features)
            t1 = time.perf_counter()
            variables.set(tokens[2], float(result))
            print(f"{tokens[2]} = {result} [Parallel sum in {t1-t0:.6f}s]")

        # --- SupremeAllocator: Alloc/Free/Status ---
        elif command == "alloc":
            # alloc <name> <size>
            if len(tokens) != 3:
                print("[Error] Usage: alloc <name> <size>")
                return
            name = tokens[1]
            size = int(tokens[2])
            try:
                buf = supreme_allocator.allocate(name, size)
                print(f"Allocated {size} bytes for '{name}'.")
            except Exception as e:
                print(f"[Allocator Error] {e}")

        elif command == "free":
            # free <name>
            if len(tokens) != 2:
                print("[Error] Usage: free <name>")
                return
            name = tokens[1]
            try:
                supreme_allocator.free_alloc(name)
                print(f"Freed buffer '{name}'.")
            except Exception as e:
                print(f"[Allocator Error] {e}")

        elif command == "alloc_status":
            # alloc_status
            print(f"Allocator status: {len(supreme_allocator.allocs)} allocations, {len(supreme_allocator.free)} free blocks.")

        # --- Async Example (future extensibility) ---
        elif command == "async_vector_add":
            # async_vector_add <var1> <var2> <resultvar>
            async def async_add():
                a = _ensure_array(variables.get(tokens[1]))
                b = _ensure_array(variables.get(tokens[2]))
                await asyncio.sleep(0)  # Simulate async
                result = supreme_vector_add(a, b, features)
                variables.set(tokens[3], result.tolist())
                print(f"{tokens[3]} = {result} [Async SIMD add]")
            asyncio.run(async_add())

        else:
            print(f"[Error] Unknown command: {command}")

    except Exception as e:
        import traceback
        print(f"[Interpreter Error] {type(e).__name__}: {e}")
        traceback.print_exc()

def generate_vector_mul(self, dest, src1, src2):
    # AVX: vmulps ymm_dest, ymm_src1, ymm_src2
    self.emit(f"    vmulps {dest}, {src1}, {src2}")

def generate_fma(self, dest, src1, src2, src3):

    # AVX: vfmadd231ps ymm_dest, ymm_src1, ymm_src2 (dest = src1 * src2 + dest)
    self.emit(f"    vfmadd231ps {dest}, {src1}, {src2}")

import threading
import ctypes
from typing import Optional

class LockFreeNode(ctypes.Structure):
    pass

LockFreeNode._fields_ = [("value", ctypes.py_object), ("next", ctypes.POINTER(LockFreeNode))]

class LockFreeStack:
    def __init__(self):
        self.top = ctypes.POINTER(LockFreeNode)()
        self.lock = threading.Lock()  # Fallback for GIL, but not used for atomic ops

    def push(self, value):
        node = LockFreeNode()
        node.value = value
        while True:
            old_top = self.top
            node.next = old_top
            if ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(id(self.top)), ctypes.py_object(node)):
                self.top = ctypes.pointer(node)
                break

    def pop(self) -> Optional[object]:
        while True:
            old_top = self.top
            if not old_top:
                return None
            next_node = old_top.contents.next
            if ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(id(self.top)), next_node):
                self.top = next_node
                return old_top.contents.value

class CodeGenerator:
    # ...
    def generate_vector_add(self, dest, src1, src2):
        # AVX2: vaddps ymm_dest, ymm_src1, ymm_src2
        self.emit(f"    vaddps {dest}, {src1}, {src2}")

    def generate_vector_mul(self, dest, src1, src2):
        # AVX2: vmulps ymm_dest, ymm_src1, ymm_src2
        self.emit(f"    vmulps {dest}, {src1}, {src2}")

class RegisterAllocator:
    def __init__(self):
        self.registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']
        self.free = set(self.registers)
        self.in_use = set()

    def alloc(self):
        if not self.free:
            raise RuntimeError("No free registers")
        reg = self.free.pop()
        self.in_use.add(reg)
        return reg

    def free_reg(self, reg):
        if reg in self.in_use:
            self.in_use.remove(reg)
            self.free.add(reg)

class MemoryPool:
    def __init__(self, block_size=4096, pool_size=1024*1024*10):
        self.block_size = block_size
        self.pool_size = pool_size
        self.pool = bytearray(pool_size)
        self.free_blocks = list(range(0, pool_size, block_size))
        self.lock = threading.Lock()
        self.alloc_map = {}

    def allocate(self, name, size):
        with self.lock:
            if not self.free_blocks:
                raise MemoryError("Out of memory in pool")
            block = self.free_blocks.pop()
            self.alloc_map[name] = (block, size)
            return memoryview(self.pool)[block:block+size]

    def free(self, name):
        with self.lock:
            if name in self.alloc_map:
                block, _ = self.alloc_map.pop(name)
                self.free_blocks.append(block)

import ctypes

libc = ctypes.CDLL("libc.so.6")
def direct_exit(status):
    libc.syscall(60, status)  # 60 is SYS_exit on x86-64

import queue

class LockFreeStack:
    def __init__(self):
        self.q = queue.SimpleQueue()

    def push(self, value):
        self.q.put(value)

    def pop(self):
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None

import numpy as np

def simd_add(a, b):
    # a, b: numpy arrays of dtype float32
    return np.add(a, b)

class CodeGenerator:
    def generate_vector_add(self, dest, src1, src2):
        # AVX2: vaddps ymm_dest, ymm_src1, ymm_src2
        self.emit(f"    vaddps {dest}, {src1}, {src2}")

class RegisterAllocator:
    def __init__(self):
        self.registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']
        self.free = set(self.registers)
        self.in_use = set()

    def alloc(self):
        if not self.free:
            raise RuntimeError("No free registers")
        reg = self.free.pop()
        self.in_use.add(reg)
        return reg

    def free_reg(self, reg):
        if reg in self.in_use:
            self.in_use.remove(reg)
            self.free.add(reg)

def generate_add(self):
    reg1 = self.reg_alloc.alloc()
    reg2 = self.reg_alloc.alloc()
    self.emit(f"    pop {reg1}")
    self.emit(f"    pop {reg2}")
    self.emit(f"    add {reg1}, {reg2}")
    self.emit(f"    push {reg1}")
    self.reg_alloc.free_reg(reg1)
    self.reg_alloc.free_reg(reg2)

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if tokens[0] == "vector_add":
        a = np.array(variables.get(tokens[1]), dtype=np.float32)
        b = np.array(variables.get(tokens[2]), dtype=np.float32)
        result = simd_add(a, b)
        variables.set(tokens[3], result.tolist())
        print(f"{tokens[3]} = {result}")

class MemoryPool:
    def __init__(self, block_size=4096, pool_size=1024*1024*10):
        self.block_size = block_size
        self.pool_size = pool_size
        self.pool = bytearray(pool_size)
        self.free_blocks = list(range(0, pool_size, block_size))
        self.lock = threading.Lock()
        self.alloc_map = {}

    def allocate(self, name, size):
        with self.lock:
            if not self.free_blocks:
                raise MemoryError("Out of memory in pool")
            block = self.free_blocks.pop()
            self.alloc_map[name] = (block, size)
            return memoryview(self.pool)[block:block+size]

    def free(self, name):
        with self.lock:
            if name in self.alloc_map:
                block, _ = self.alloc_map.pop(name)
                self.free_blocks.append(block)

import queue

class LockFreeStack:
    def __init__(self):
        self.q = queue.SimpleQueue()

    def push(self, value):
        self.q.put(value)

    def pop(self):
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None

import queue

class LockFreeQueue:
    def __init__(self):
        self.q = queue.SimpleQueue()

    def enqueue(self, value):
        self.q.put(value)

    def dequeue(self):
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None

# interpreter_visual.py

import queue

class LockFreeStack:
    def __init__(self):
        self.q = queue.SimpleQueue()

    def push(self, value):
        self.q.put(value)

    def pop(self):
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None

