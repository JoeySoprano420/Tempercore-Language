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

class Concurrency:
    def __init__(self):
        self.extensions = [
            WebExtension(),
            GUIExtension(),
            MLExtension(),
            MobileExtension(),
            GameExtension()
        ]
    def handle(self, tokens):
        for ext in self.extensions:
            if ext.handle(tokens):
                return True
        return False
    def help(self):
        return "\n".join(ext.help() for ext in self.extensions)

import threading
from stdlib import TempercoreStdLib as T

# ------------------ STACK ------------------
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

# ------------------ HEAP ------------------
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

# ------------------ EXTENSION SYSTEM ------------------
class Extension:
    def handle(self, tokens):
        raise NotImplementedError
    def help(self):
        return ""

class WebExtension(Extension):
    def handle(self, tokens):
        if tokens[0] == "web":
            if len(tokens) < 2:
                print("[Web] Missing subcommand.")
                return True
            cmd = tokens[1]
            if cmd == "serve":
                print(f"[Web] Simulating web server at {tokens[2] if len(tokens) > 2 else '<missing address>'}")
            elif cmd == "request":
                print(f"[Web] Simulating HTTP request to {tokens[2] if len(tokens) > 2 else '<missing url>'}")
            elif cmd == "socket":
                print(f"[Web] Simulating websocket connection to {tokens[2] if len(tokens) > 2 else '<missing url>'}")
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
            cmd = tokens[1]
            rest = " ".join(tokens[2:])
            if cmd == "window":
                print(f"[GUI] Simulating window with title: {rest}")
            elif cmd == "button":
                print(f"[GUI] Simulating button: {rest}")
            elif cmd == "label":
                print(f"[GUI] Simulating label: {rest}")
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
            cmd = tokens[1]
            if cmd == "train":
                print(f"[ML] Simulating model training on data: {tokens[2] if len(tokens) > 2 else '<missing data>'}")
            elif cmd == "predict":
                print(f"[ML] Simulating prediction for input: {tokens[2] if len(tokens) > 2 else '<missing input>'}")
            elif cmd == "evaluate":
                print(f"[ML] Simulating model evaluation on: {tokens[2] if len(tokens) > 2 else '<missing data>'}")
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
            cmd = tokens[1]
            if cmd == "build":
                print(f"[Mobile] Simulating mobile app build for: {tokens[2] if len(tokens) > 2 else '<missing platform>'}")
            elif cmd == "deploy":
                print(f"[Mobile] Simulating deployment to: {tokens[2] if len(tokens) > 2 else '<missing device>'}")
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
            cmd = tokens[1]
            rest = " ".join(tokens[2:])
            if cmd == "start":
                print("[Game] Simulating game engine start")
            elif cmd == "entity":
                print(f"[Game] Simulating entity creation: {rest}")
            elif cmd == "event":
                print(f"[Game] Simulating game event: {rest}")
            else:
                print("[Game] Unknown game command")
            return True
        return False
    def help(self):
        return "game start, game entity <name>, game event <event>"

class Concurrency:
    def __init__(self):
        self.extensions = [
            WebExtension(),
            GUIExtension(),
            MLExtension(),
            MobileExtension(),
            GameExtension()
        ]
    def handle(self, tokens):
        for ext in self.extensions:
            if ext.handle(tokens):
                return True
        return False
    def help(self):
        return "\n".join(ext.help() for ext in self.extensions)

# ------------------ INTERPRETER ------------------
stack = Stack()
heap = Heap()
ext = Concurrency()
stdlib = T()

def run_command(line):
    tokens = line.strip().split()
    if not tokens:
        return
    cmd = tokens[0]

    # --- Extension Hook ---
    if ext.handle(tokens):
        return

    # --- Stack Commands ---
    if cmd == "push":
        val = " ".join(tokens[1:])
        stack.push(val)
    elif cmd == "pop":
        print("Popped:", stack.pop())
    elif cmd == "peek":
        print("Top:", stack.peek())
    elif cmd == "clear":
        stack.clear()

    # --- Heap Commands ---
    elif cmd == "alloc":
        if len(tokens) >= 3:
            heap.allocate(tokens[1], " ".join(tokens[2:]))
        else:
            print("Usage: alloc <name> <value>")
    elif cmd == "get":
        print(heap.retrieve(tokens[1]) if len(tokens) > 1 else "Usage: get <name>")
    elif cmd == "del":
        heap.delete(tokens[1] if len(tokens) > 1 else "")
    elif cmd == "hclear":
        heap.clear()
    elif cmd == "hdump":
        print(heap.dump())

    # --- Stdlib Hooks ---
    elif cmd == "std":
        result = stdlib.execute(tokens[1:])
        if result is not None:
            print("[STDLIB]", result)

    # --- Help ---
    elif cmd == "help":
        print("[Built-in] push/pop/peek/clear, alloc/get/del/hclear/hdump")
        print("[Stdlib] std <function> <args...>")
        print("[Extensions]")
        print(ext.help())

    else:
        print("Unknown command:", cmd)

# ------------------ MAIN LOOP ------------------
if __name__ == "__main__":
    print("Tempercore Interpreter 🔥")
    print("Type 'help' for command list.")
    while True:
        try:
            line = input(">> ").strip()
            if line in {"exit", "quit"}:
                break
            run_command(line)
        except Exception as e:
            print("Error:", e)
