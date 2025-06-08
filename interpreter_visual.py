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

        
